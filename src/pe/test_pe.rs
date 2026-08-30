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
        0x48, 0x83, 0xEC, 0x28,
        0x48, 0x8D, 0x0D, 0x10, 0x00, 0x00, 0x00,
        0xFF, 0x15, 0x02, 0x00, 0x00, 0x00,
        0x31, 0xC0,
        0x48, 0x83, 0xC4, 0x28,
        0xC3,
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

    let text_data = vec![0x90; 0x200];
    pe.extend_from_slice(&text_data);

    let data_data = vec![0x00; 0x200];
    pe.extend_from_slice(&data_data);

    let overlay = b"DEBUG_DATA_OVERLAY";
    pe.extend_from_slice(overlay);
    
    pe.extend_from_slice(&vec![0xAA; 512]);

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
    let mut header = vec![0u8; 240];
    header[0] = 0x0B;
    header[1] = 0x02;
    header[2] = 14;
    header[3] = 0;
    
    header[16] = 0x00;
    header[17] = 0x10;
    header[18] = 0x00;
    header[19] = 0x00;
    
    header[24] = 0x00;
    header[25] = 0x10;
    header[26] = 0x00;
    header[27] = 0x00;
    
    header[28] = 0x00;
    header[29] = 0x10;
    header[30] = 0x00;
    header[31] = 0x00;
    
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
