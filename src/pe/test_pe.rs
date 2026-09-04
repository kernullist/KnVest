pub fn create_minimal_pe64() -> Vec<u8> {
    let mut pe = Vec::new();

    let dos_header = create_dos_header(0x80);
    pe.extend_from_slice(&dos_header);

    let dos_stub = vec![0u8; 0x80 - dos_header.len()];
    pe.extend_from_slice(&dos_stub);

    let pe_signature = b"PE\0\0";
    pe.extend_from_slice(pe_signature);

    let coff_header = create_coff_header(1);
    pe.extend_from_slice(&coff_header);

    let optional_header = create_optional_header_pe32plus();
    pe.extend_from_slice(&optional_header);

    let text_section_header = create_section_header(
        b".text\0\0\0",
        0x1000,
        0x1000,
        0x200,
        0x400,
    );
    pe.extend_from_slice(&text_section_header);

    while pe.len() < 0x400 {
        pe.push(0);
    }

    let section_data = vec![
        0x55, // push rbp
        0x48, 0x89, 0xE5, // mov rbp, rsp
        0x48, 0x83, 0xEC, 0x20, // sub rsp, 0x20
        0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, 0
        0x48, 0x83, 0xC4, 0x20, // add rsp, 0x20
        0x5D, // pop rbp
        0xC3, // ret
    ];
    pe.extend_from_slice(&section_data);

    while pe.len() < 0x600 {
        pe.push(0);
    }

    pe
}

pub fn create_pe64_with_overlay() -> Vec<u8> {
    let mut pe = Vec::new();

    let dos_header = create_dos_header(0x80);
    pe.extend_from_slice(&dos_header);

    let dos_stub = vec![0u8; 0x80 - dos_header.len()];
    pe.extend_from_slice(&dos_stub);

    let pe_signature = b"PE\0\0";
    pe.extend_from_slice(pe_signature);

    let coff_header = create_coff_header(2);
    pe.extend_from_slice(&coff_header);

    let optional_header = create_optional_header_pe32plus();
    pe.extend_from_slice(&optional_header);

    let text_section_header = create_section_header(
        b".text\0\0\0",
        0x100,
        0x1000,
        0x200,
        0x400,
    );
    pe.extend_from_slice(&text_section_header);

    let data_section_header = create_section_header(
        b".data\0\0\0",
        0x100,
        0x2000,
        0x200,
        0x600,
    );
    pe.extend_from_slice(&data_section_header);

    while pe.len() < 0x400 {
        pe.push(0);
    }

    let mut text_data = vec![0x90; 0x200];
    text_data[0] = 0x55;
    text_data[1] = 0x48;
    text_data[2] = 0x89;
    text_data[3] = 0xE5;
    text_data[4] = 0x31;
    text_data[5] = 0xC0;
    text_data[6] = 0x5D;
    text_data[7] = 0xC3;
    pe.extend_from_slice(&text_data);

    let data_data = vec![0x00; 0x200];
    pe.extend_from_slice(&data_data);

    let overlay = b"DEBUG_DATA_OVERLAY";
    pe.extend_from_slice(overlay);
    
    pe.extend_from_slice(&vec![0xAA; 512]);

    pe
}

/// PE64 with a minimal msvcrt `puts` import for IAT unit tests.
pub fn create_pe64_with_imports() -> Vec<u8> {
    let mut pe = Vec::new();

    pe.extend_from_slice(&create_dos_header(0x80));
    pe.extend_from_slice(&vec![0u8; 0x80 - 64]);

    pe.extend_from_slice(b"PE\0\0");
    pe.extend_from_slice(&create_coff_header(2));

    // Import directory at RVA 0x3000
    pe.extend_from_slice(&create_optional_header_pe32plus_with_import_dir(0x3000, 0x80));

    pe.extend_from_slice(&create_section_header(
        b".text\0\0\0",
        0x200,
        0x1000,
        0x200,
        0x400,
    ));
    pe.extend_from_slice(&create_section_header(
        b".idata\0\0",
        0x200,
        0x3000,
        0x200,
        0x600,
    ));

    while pe.len() < 0x400 {
        pe.push(0);
    }

    // main: push rbp; mov rbp,rsp; sub rsp,0x28; lea rcx,[rip+0x1000]; call [puts_iat]; xor eax,eax; leave; ret
    let puts_iat_rva = 0x3038u32;
    let call_disp = 0i32; // patched after main bytes are placed
    let mut text = vec![0x90u8; 0x200];
    let main = [
        0x55, 0x48, 0x89, 0xE5, // push rbp; mov rbp, rsp
        0x48, 0x83, 0xEC, 0x28, // sub rsp, 0x28
        0x48, 0x8D, 0x0D, 0xF0, 0x0F, 0x00, 0x00, // lea rcx, [rip+0xFF0] -> .rdata str
        0xFF, 0x15, // call [rip+disp32]
    ];
    text[0..main.len()].copy_from_slice(&main);
    let call_pos = text
        .windows(2)
        .position(|w| w == [0xFF, 0x15])
        .expect("call [rip+disp] in fixture");
    let call_end_rva = 0x1000 + call_pos as u32 + 6;
    let call_disp = (puts_iat_rva as i32) - (call_end_rva as i32);
    text[call_pos + 2..call_pos + 6].copy_from_slice(&call_disp.to_le_bytes());
    text[main.len() + 4] = 0x31; // xor eax,eax (xor eax,eax is 31 C0)
    text[main.len() + 5] = 0xC0;
    text[main.len() + 6] = 0x48; // leave-ish: add rsp,0x28; pop rbp; ret
    text[main.len() + 7] = 0x83;
    text[main.len() + 8] = 0xC4;
    text[main.len() + 9] = 0x28;
    text[main.len() + 10] = 0x5D;
    text[main.len() + 11] = 0xC3;
    pe.extend_from_slice(&text);

    while pe.len() < 0x600 {
        pe.push(0);
    }

    // .idata layout: descriptor(20) + null descriptor(20) + ILT + IAT + names
    let mut idata = vec![0u8; 0x200];
    let base_rva = 0x3000u32;

    let ilt_rva = base_rva + 0x28;
    let iat_rva = base_rva + 0x38;
    let dll_name_rva = base_rva + 0x48;
    let hint_name_rva = base_rva + 0x58;

    // IMAGE_IMPORT_DESCRIPTOR at RVA 0x3000
    idata[0..4].copy_from_slice(&ilt_rva.to_le_bytes());
    idata[12..16].copy_from_slice(&dll_name_rva.to_le_bytes());
    idata[16..20].copy_from_slice(&iat_rva.to_le_bytes());
    // null terminator descriptor at 0x14 is already zero

    // ILT: one thunk -> hint/name
    let ilt_off = 0x28usize;
    idata[ilt_off..ilt_off + 8].copy_from_slice(&(hint_name_rva as u64).to_le_bytes());

    // IAT: placeholder pointer (filled by loader)
    let iat_off = 0x38usize;
    idata[iat_off..iat_off + 8].copy_from_slice(&0xDEAD_BEEF_CAFE_BABEu64.to_le_bytes());

    // DLL name
    let dll_off = 0x48usize;
    idata[dll_off..dll_off + 11].copy_from_slice(b"msvcrt.dll\0");

    // hint + name "puts"
    let hn_off = 0x58usize;
    idata[hn_off + 2..hn_off + 7].copy_from_slice(b"puts\0");

    pe.extend_from_slice(&idata);

    while pe.len() < 0x800 {
        pe.push(0);
    }

    pe
}

/// PE64 with main calling an internal callee (CFG collection test).
pub fn create_pe64_with_callee() -> Vec<u8> {
    let mut pe = Vec::new();

    pe.extend_from_slice(&create_dos_header(0x80));
    pe.extend_from_slice(&vec![0u8; 0x80 - 64]);

    pe.extend_from_slice(b"PE\0\0");
    pe.extend_from_slice(&create_coff_header(1));
    pe.extend_from_slice(&create_optional_header_pe32plus());

    pe.extend_from_slice(&create_section_header(
        b".text\0\0\0",
        0x400,
        0x1000,
        0x400,
        0x400,
    ));

    while pe.len() < 0x400 {
        pe.push(0);
    }

    let mut text = vec![0x90u8; 0x400];

    // callee at .text+0x00: mov eax, 7; ret (prologue-less)
    text[0x10] = 0xB8;
    text[0x11] = 0x07;
    text[0x12] = 0x00;
    text[0x13] = 0x00;
    text[0x14] = 0x00;
    text[0x15] = 0xC3;

    // main at .text+0x20: push rbp; mov rbp,rsp; call callee; pop rbp; ret
    let main_off = 0x20usize;
    let call_from = main_off + 4; // after push rbp + mov rbp,rsp
    let call_end = call_from + 5;
    let callee_off = 0x10usize;
    let rel = (callee_off as i32) - (call_end as i32);
    text[main_off] = 0x55;
    text[main_off + 1] = 0x48;
    text[main_off + 2] = 0x89;
    text[main_off + 3] = 0xE5;
    text[call_from] = 0xE8;
    text[call_from + 1..call_from + 5].copy_from_slice(&rel.to_le_bytes());
    text[call_from + 5] = 0x5D;
    text[call_from + 6] = 0xC3;

    pe.extend_from_slice(&text);

    while pe.len() < 0x800 {
        pe.push(0);
    }

    pe
}

/// PE64 with main that `call rel32`s forward into fake CRT — must not be CFG-collected.
pub fn create_pe64_with_forward_crt_call() -> Vec<u8> {
    let mut pe = Vec::new();

    pe.extend_from_slice(&create_dos_header(0x80));
    pe.extend_from_slice(&vec![0u8; 0x80 - 64]);
    pe.extend_from_slice(b"PE\0\0");
    pe.extend_from_slice(&create_coff_header(1));
    pe.extend_from_slice(&create_optional_header_pe32plus());
    pe.extend_from_slice(&create_section_header(
        b".text\0\0\0",
        0x800,
        0x1000,
        0x800,
        0x400,
    ));

    while pe.len() < 0x400 {
        pe.push(0);
    }

    let mut text = vec![0x90u8; 0x800];
    // fake CRT at .text+0x400
    text[0x400] = 0x55;
    text[0x401] = 0x48;
    text[0x402] = 0x89;
    text[0x403] = 0xE5;
    text[0x404] = 0xB8;
    text[0x409] = 0xC3;

    // main at .text+0x20
    let main_off = 0x20usize;
    let crt_off = 0x400usize;
    let call_from = main_off + 4;
    let call_end = call_from + 5;
    let rel = (crt_off as i32) - (call_end as i32);
    text[main_off] = 0x55;
    text[main_off + 1] = 0x48;
    text[main_off + 2] = 0x89;
    text[main_off + 3] = 0xE5;
    text[call_from] = 0xE8;
    text[call_from + 1..call_from + 5].copy_from_slice(&rel.to_le_bytes());
    text[call_from + 5] = 0x5D;
    text[call_from + 6] = 0xC3;

    pe.extend_from_slice(&text);
    while pe.len() < 0xC00 {
        pe.push(0);
    }
    pe
}

/// PE64 with `call rel32` to an FF 25 import thunk for puts.
pub fn create_pe64_with_puts_thunk_call() -> Vec<u8> {
    let mut pe = create_pe64_with_imports();
    let pe_file = crate::pe::parser::PEFile::from_bytes(pe.clone()).unwrap();
    let imports = pe_file.parse_imports().unwrap();
    let puts = imports.entries().iter().find(|e| e.name == "puts").unwrap();
    let text = pe_file.get_section(".text").unwrap();
    let text_off = pe_file.rva_to_file_offset(text.virtual_address).unwrap();

    // Place FF 25 thunk at .text+0x80
    let thunk_off = text_off + 0x80;
    pe[thunk_off] = 0xFF;
    pe[thunk_off + 1] = 0x25;
    let disp = (puts.iat_rva as i32) - ((text.virtual_address + 0x80 + 6) as i32);
    pe[thunk_off + 2..thunk_off + 6].copy_from_slice(&disp.to_le_bytes());

    // main: push rbp; mov rbp,rsp; call thunk; xor eax,eax; pop rbp; ret
    let main_off = text_off + 0x20;
    let call_from = main_off + 4;
    let call_end = call_from + 5;
    let rel = (thunk_off as i32) - (call_end as i32);
    pe[main_off] = 0x55;
    pe[main_off + 1] = 0x48;
    pe[main_off + 2] = 0x89;
    pe[main_off + 3] = 0xE5;
    pe[call_from] = 0xE8;
    pe[call_from + 1..call_from + 5].copy_from_slice(&rel.to_le_bytes());
    pe[call_from + 5] = 0x31;
    pe[call_from + 6] = 0xC0;
    pe[call_from + 7] = 0x5D;
    pe[call_from + 8] = 0xC3;

    pe
}

fn create_dos_header(pe_offset: u32) -> Vec<u8> {
    let mut header = vec![0u8; 64];
    header[0] = b'M';
    header[1] = b'Z';
    header[2] = 0x90;
    header[3] = 0x00;
    header[4] = 0x03;
    header[5] = 0x00;
    header[0x3C] = (pe_offset & 0xFF) as u8;
    header[0x3D] = ((pe_offset >> 8) & 0xFF) as u8;
    header[0x3E] = ((pe_offset >> 16) & 0xFF) as u8;
    header[0x3F] = ((pe_offset >> 24) & 0xFF) as u8;
    header
}

fn create_coff_header(num_sections: u16) -> Vec<u8> {
    let mut header = vec![0u8; 20];
    header[0] = 0x64;
    header[1] = 0x86;
    header[2] = (num_sections & 0xFF) as u8;
    header[3] = ((num_sections >> 8) & 0xFF) as u8;
    header[16] = 0xF0;
    header[17] = 0x00;
    header[18] = 0x22;
    header[19] = 0x00;
    header
}

fn create_optional_header_pe32plus() -> Vec<u8> {
    create_optional_header_pe32plus_with_import_dir(0, 0)
}

fn create_optional_header_pe32plus_with_import_dir(import_rva: u32, import_size: u32) -> Vec<u8> {
    let mut header = vec![0u8; 240];
    header[0] = 0x0B;
    header[1] = 0x02;
    header[2] = 14;
    header[3] = 0;
    
    header[16] = 0x00;
    header[17] = 0x10;
    header[18] = 0x00;
    header[19] = 0x00;
    
    // ImageBase = 0x140000000
    header[24] = 0x00;
    header[25] = 0x00;
    header[26] = 0x00;
    header[27] = 0x40;
    header[28] = 0x01;
    header[29] = 0x00;
    header[30] = 0x00;
    header[31] = 0x00;
    
    // Data directory[1] = Import Table
    let import_dir_off = 112 + 8;
    header[import_dir_off..import_dir_off + 4].copy_from_slice(&import_rva.to_le_bytes());
    header[import_dir_off + 4..import_dir_off + 8].copy_from_slice(&import_size.to_le_bytes());
    
    header
}

fn create_section_header(
    name: &[u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
) -> Vec<u8> {
    let mut header = vec![0u8; 40];
    header[0..8].copy_from_slice(name);
    
    header[8..12].copy_from_slice(&virtual_size.to_le_bytes());
    header[12..16].copy_from_slice(&virtual_address.to_le_bytes());
    header[16..20].copy_from_slice(&size_of_raw_data.to_le_bytes());
    header[20..24].copy_from_slice(&pointer_to_raw_data.to_le_bytes());
    
    header[36] = 0x20;
    header[37] = 0x00;
    header[38] = 0x00;
    header[39] = 0x60;
    
    header
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::parser::PEFile;

    #[test]
    fn test_minimal_pe_is_valid() {
        let pe_data = create_minimal_pe64();
        let result = PEFile::from_bytes(pe_data);
        assert!(result.is_ok());
        let pe = result.unwrap();
        assert_eq!(pe.entry_point_rva, 0x1000);
    }

    #[test]
    fn test_minimal_pe_has_text_section() {
        let pe_data = create_minimal_pe64();
        let pe = PEFile::from_bytes(pe_data).unwrap();
        let section = pe.get_section(".text");
        assert!(section.is_ok());
    }

    #[test]
    fn test_pe_with_overlay_is_valid() {
        let pe_data = create_pe64_with_overlay();
        let result = PEFile::from_bytes(pe_data);
        assert!(result.is_ok());
        let pe = result.unwrap();
        assert_eq!(pe.num_sections, 2);
    }
}
