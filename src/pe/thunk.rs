use super::imports::ImportTable;
use super::parser::PEFile;

/// `jmp [rip+disp32]` import thunk (MinGW/MSVC `.text` stub).
pub fn is_import_thunk_at(pe: &PEFile, file_offset: usize) -> bool {
    iat_slot_rva_from_thunk(pe, file_offset).is_some()
}

/// Decode `FF 25` / `REX.W FF 25` thunk at `file_offset` → IAT slot RVA.
pub fn iat_slot_rva_from_thunk(pe: &PEFile, file_offset: usize) -> Option<u32> {
    let data = &pe.data;
    let (insn_len, disp_off) = if file_offset + 7 <= data.len()
        && data[file_offset] == 0x48
        && data[file_offset + 1] == 0xFF
        && data[file_offset + 2] == 0x25
    {
        (7usize, file_offset + 3)
    } else if file_offset + 6 <= data.len()
        && data[file_offset] == 0xFF
        && data[file_offset + 1] == 0x25
    {
        (6, file_offset + 2)
    } else {
        return None;
    };
    if disp_off + 4 > data.len() {
        return None;
    }
    let disp = i32::from_le_bytes(data[disp_off..disp_off + 4].try_into().ok()?);
    let thunk_rva = pe.file_offset_to_rva(file_offset).ok()?;
    Some((thunk_rva as i64 + insn_len as i64 + disp as i64) as u32)
}

/// True when `target_file_offset` must not be lifted (import thunk / IAT slot).
pub fn is_non_liftable_target(pe: &PEFile, imports: &ImportTable, target_file_offset: usize) -> bool {
    if is_import_thunk_at(pe, target_file_offset) {
        return true;
    }
    if let Some(slot) = iat_slot_rva_from_thunk(pe, target_file_offset) {
        if imports.lookup_iat_rva(slot).is_some() || pe.resolve_iat_target(imports, slot).is_some()
        {
            return true;
        }
    }
    if let Ok(rva) = pe.file_offset_to_rva(target_file_offset) {
        if imports.lookup_iat_rva(rva).is_some() {
            return true;
        }
        if pe.resolve_iat_target(imports, rva).is_some() {
            return true;
        }
    }
    false
}

/// Resolve IAT slot RVA for a `call rel32` landing on a text thunk.
pub fn iat_rva_for_call_target(
    pe: &PEFile,
    imports: &ImportTable,
    target_file_offset: usize,
) -> Option<u32> {
    if let Some(slot) = iat_slot_rva_from_thunk(pe, target_file_offset) {
        if let Some(entry) = pe.resolve_iat_target(imports, slot) {
            return Some(entry.iat_rva);
        }
        if imports.lookup_iat_rva(slot).is_some() {
            return Some(slot);
        }
    }
    let rva = pe.file_offset_to_rva(target_file_offset).ok()?;
    pe.resolve_iat_target(imports, rva).map(|e| e.iat_rva)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::parser::PEFile;
    use crate::pe::test_pe;

    #[test]
    fn detects_ff25_thunk() {
        let pe_data = test_pe::create_pe64_with_imports();
        let pe = PEFile::from_bytes(pe_data).unwrap();
        let text = pe.get_section(".text").unwrap();
        let text_off = pe.rva_to_file_offset(text.virtual_address).unwrap();
        // fixture has call [rip+disp] not jmp thunk in .text — use synthetic bytes
        let mut data = pe.data.clone();
        let t = text_off + 0x80;
        data[t] = 0xFF;
        data[t + 1] = 0x25;
        let imports = pe.parse_imports().unwrap();
        let puts = imports.entries().iter().find(|e| e.name == "puts").unwrap();
        let disp = (puts.iat_rva as i32) - ((text.virtual_address + 0x80 + 6) as i32);
        data[t + 2..t + 6].copy_from_slice(&disp.to_le_bytes());
        let pe2 = PEFile::from_bytes(data).unwrap();
        assert!(is_import_thunk_at(&pe2, t));
        assert_eq!(
            iat_slot_rva_from_thunk(&pe2, t),
            Some(puts.iat_rva)
        );
    }
}
