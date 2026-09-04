use super::parser::{PEError, PEFile, PEResult};
use std::collections::HashMap;

/// One imported symbol resolved from the PE import directory / IAT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportEntry {
    pub dll_name: String,
    pub name: String,
    /// RVA of the IAT slot (FirstThunk) that holds the resolved function pointer.
    pub iat_rva: u32,
}

/// Parsed import table with fast IAT-RVA lookup.
#[derive(Debug, Clone, Default)]
pub struct ImportTable {
    entries: Vec<ImportEntry>,
    by_iat_rva: HashMap<u32, usize>,
}

/// func_id values 1..3 are legacy WriteFile/print helpers; bit 32 marks IAT win64 calls.
pub const NATIVE_CALL_IAT_TAG: u64 = 0x1_0000_0000;

pub fn native_call_iat_id(iat_rva: u32) -> u64 {
    NATIVE_CALL_IAT_TAG | (iat_rva as u64)
}

pub fn is_iat_native_call(func_id: u64) -> bool {
    func_id >= NATIVE_CALL_IAT_TAG
}

pub fn iat_rva_from_native_call(func_id: u64) -> u32 {
    (func_id & 0xFFFF_FFFF) as u32
}

/// CRT / startup imports that should not be lifted to native_call.
pub const CRT_SKIP_NAMES: &[&str] = &[
    "__main",
    "_main",
    "__libc_start_main",
    "_initterm",
    "_initterm_e",
    "__getmainargs",
    "__p__environ",
    "__p___argc",
    "__p___argv",
    "SetUnhandledExceptionFilter",
    "_pei386_runtime_relocator",
    "__mingw_init_ehandler",
    "_gnu_exception_handler",
    "atexit",
    "_onexit",
    "_register_onexit_function",
    "__do_global_dtors",
    "__do_global_ctors",
    "_DllMainCRTStartup",
    "__mingw_raise_wrong_version",
    "_configure_narrow_argv",
    "_initialize_narrow_environment",
    "_configure_wide_argv",
    "_initialize_wide_environment",
    "_execute_onexit_table",
    "_register_thread_local_exe_atexit_callback",
    "_crt_atexit",
    "_cexit",
    "_c_exit",
    "_exit",
    "_amsg_exit",
    "__set_app_type",
    "__setusermatherr",
    "_configthreadlocale",
    "_initterm",
    "__main",
    "mainCRTStartup",
    "WinMainCRTStartup",
    "wWinMainCRTStartup",
];

impl ImportTable {
    pub fn entries(&self) -> &[ImportEntry] {
        &self.entries
    }

    pub fn lookup_iat_rva(&self, rva: u32) -> Option<&ImportEntry> {
        self.by_iat_rva.get(&rva).map(|&i| &self.entries[i])
    }

    pub fn is_crt_startup(&self, entry: &ImportEntry) -> bool {
        is_crt_import_name(&entry.name)
    }
}

pub fn is_crt_import_name(name: &str) -> bool {
    CRT_SKIP_NAMES.iter().any(|&n| n == name)
        || name.starts_with("__mingw")
        || name.starts_with("_init")
        || name.ends_with("_crt_startup")
}

impl PEFile {
    /// Read ImageBase from the PE32+ optional header.
    pub fn image_base(&self) -> u64 {
        let off = self.optional_header_offset + 24;
        if off + 8 > self.data.len() {
            return 0x1400_0000;
        }
        u64::from_le_bytes(self.data[off..off + 8].try_into().unwrap_or([0; 8]))
    }

    /// RVA of the import data directory, if present.
    pub fn import_directory_rva(&self) -> Option<u32> {
        let off = self.optional_header_offset + 112 + 8; // data directory[1]
        if off + 8 > self.data.len() {
            return None;
        }
        let rva = u32::from_le_bytes(self.data[off..off + 4].try_into().ok()?);
        let size = u32::from_le_bytes(self.data[off + 4..off + 8].try_into().ok()?);
        if rva == 0 || size == 0 {
            None
        } else {
            Some(rva)
        }
    }

    /// Parse the PE import directory and build an IAT lookup table.
    pub fn parse_imports(&self) -> PEResult<ImportTable> {
        let import_rva = match self.import_directory_rva() {
            Some(r) => r,
            None => return Ok(ImportTable::default()),
        };
        let import_off = self.rva_to_file_offset(import_rva)?;

        let mut table = ImportTable::default();

        let mut desc_off = import_off;
        loop {
            if desc_off + 20 > self.data.len() {
                break;
            }
            let original_first_thunk = u32::from_le_bytes(
                self.data[desc_off..desc_off + 4]
                    .try_into()
                    .map_err(|_| PEError::InvalidPE("import descriptor".into()))?,
            );
            let name_rva = u32::from_le_bytes(
                self.data[desc_off + 12..desc_off + 16]
                    .try_into()
                    .map_err(|_| PEError::InvalidPE("import descriptor".into()))?,
            );
            let first_thunk = u32::from_le_bytes(
                self.data[desc_off + 16..desc_off + 20]
                    .try_into()
                    .map_err(|_| PEError::InvalidPE("import descriptor".into()))?,
            );

            if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
                break;
            }
            if original_first_thunk == 0 && first_thunk == 0 {
                break;
            }

            let dll_name = read_cstring_at_rva(self, name_rva).unwrap_or_default();
            let ilt_rva = if original_first_thunk != 0 {
                original_first_thunk
            } else {
                first_thunk
            };

            let mut thunk_off = self.rva_to_file_offset(ilt_rva)?;
            let mut iat_rva = first_thunk;

            loop {
                if thunk_off + 8 > self.data.len() {
                    break;
                }
                let thunk_val = u64::from_le_bytes(
                    self.data[thunk_off..thunk_off + 8]
                        .try_into()
                        .map_err(|_| PEError::InvalidPE("import thunk".into()))?,
                );
                if thunk_val == 0 {
                    break;
                }

                let name = if thunk_val & (1u64 << 63) != 0 {
                    format!("ord_{}", thunk_val & 0xFFFF)
                } else {
                    let hint_name_rva = thunk_val as u32;
                    read_hint_name_at_rva(self, hint_name_rva).unwrap_or_default()
                };

                if !name.is_empty() {
                    let idx = table.entries.len();
                    table.entries.push(ImportEntry {
                        dll_name: dll_name.clone(),
                        name,
                        iat_rva,
                    });
                    table.by_iat_rva.insert(iat_rva, idx);
                }

                thunk_off += 8;
                iat_rva += 8;
            }

            desc_off += 20;
        }

        Ok(table)
    }

    /// Resolve a call/jmp target RVA to an import entry when it lands in the IAT.
    pub fn resolve_iat_target<'a>(
        &self,
        imports: &'a ImportTable,
        target_rva: u32,
    ) -> Option<&'a ImportEntry> {
        if let Some(e) = imports.lookup_iat_rva(target_rva) {
            return Some(e);
        }
        for delta in [-8i32, 8] {
            let rva = (target_rva as i64 + delta as i64) as u32;
            if let Some(e) = imports.lookup_iat_rva(rva) {
                return Some(e);
            }
        }
        // nearest IAT slot within one pointer width (disassembly boundary slop)
        imports
            .entries()
            .iter()
            .min_by_key(|e| (target_rva as i64 - e.iat_rva as i64).unsigned_abs())
            .filter(|e| (target_rva as i64 - e.iat_rva as i64).unsigned_abs() <= 8)
    }
}

fn read_cstring_at_rva(pe: &PEFile, rva: u32) -> PEResult<String> {
    let off = pe.rva_to_file_offset(rva)?;
    let end = pe.data[off..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| off + p)
        .unwrap_or(pe.data.len());
    Ok(String::from_utf8_lossy(&pe.data[off..end]).into_owned())
}

fn read_hint_name_at_rva(pe: &PEFile, rva: u32) -> PEResult<String> {
    let off = pe.rva_to_file_offset(rva)?;
    // Skip 2-byte hint.
    if off + 2 >= pe.data.len() {
        return Err(PEError::InvalidPE("hint/name truncated".into()));
    }
    let name_off = off + 2;
    let end = pe.data[name_off..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| name_off + p)
        .unwrap_or(pe.data.len());
    Ok(String::from_utf8_lossy(&pe.data[name_off..end]).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::test_pe;

    #[test]
    fn debug_import_pe_layout() {
        let pe_data = test_pe::create_pe64_with_imports();
        let pe = PEFile::from_bytes(pe_data.clone()).unwrap();
        assert_eq!(pe.import_directory_rva(), Some(0x3000));
        let import_off = pe.rva_to_file_offset(0x3000).unwrap();
        let ilt = u32::from_le_bytes(pe.data[import_off..import_off + 4].try_into().unwrap());
        let iat = u32::from_le_bytes(pe.data[import_off + 16..import_off + 20].try_into().unwrap());
        assert_eq!(ilt, 0x3028, "ILT RVA");
        assert_eq!(iat, 0x3038, "IAT RVA");
        let thunk = u64::from_le_bytes(
            pe.data[pe.rva_to_file_offset(ilt).unwrap()..][..8].try_into().unwrap(),
        );
        assert_eq!(thunk, 0x3058, "first thunk -> hint/name");
    }

    #[test]
    fn parse_imports_finds_puts() {
        let pe_data = test_pe::create_pe64_with_imports();
        let pe = PEFile::from_bytes(pe_data).unwrap();
        let imports = pe.parse_imports().unwrap();
        let puts = imports
            .entries()
            .iter()
            .find(|e| e.name == "puts")
            .expect("puts import");
        assert!(
            puts.dll_name.to_lowercase().contains("msvcrt")
                || puts.dll_name.to_lowercase().contains("ucrtbase")
                || puts.dll_name.contains(".dll"),
            "dll: {}",
            puts.dll_name
        );
        assert!(imports.lookup_iat_rva(puts.iat_rva).is_some());
    }

    #[test]
    fn iat_native_call_id_roundtrip() {
        let id = native_call_iat_id(0x3000);
        assert!(is_iat_native_call(id));
        assert_eq!(iat_rva_from_native_call(id), 0x3000);
        assert!(!is_iat_native_call(2));
    }

    #[test]
    fn crt_skip_names() {
        assert!(is_crt_import_name("__main"));
        assert!(is_crt_import_name("_initterm"));
        assert!(!is_crt_import_name("puts"));
        assert!(!is_crt_import_name("printf"));
    }

    #[test]
    fn resolve_iat_target_by_rva() {
        let pe_data = test_pe::create_pe64_with_imports();
        let pe = PEFile::from_bytes(pe_data).unwrap();
        let imports = pe.parse_imports().unwrap();
        let puts = imports.entries().iter().find(|e| e.name == "puts").unwrap();
        let resolved = pe.resolve_iat_target(&imports, puts.iat_rva);
        assert!(resolved.is_some());
        assert_eq!(resolved.unwrap().name, "puts");
    }
}
