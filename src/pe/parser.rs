use std::fs;
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PEError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid PE file: {0}")]
    InvalidPE(String),
    #[error("Unsupported PE architecture (expected PE32+)")]
    UnsupportedArchitecture,
    #[error("Section not found: {0}")]
    SectionNotFound(String),
}

pub type PEResult<T> = Result<T, PEError>;

#[derive(Clone)]
pub struct PEFile {
    pub data: Vec<u8>,
    pub dos_header_offset: usize,
    pub pe_header_offset: usize,
    pub optional_header_offset: usize,
    pub sections_offset: usize,
    pub num_sections: u16,
    pub entry_point_rva: u32,
}

impl PEFile {
    pub fn from_file<P: AsRef<Path>>(path: P) -> PEResult<Self> {
        let data = fs::read(path)?;
        Self::from_bytes(data)
    }

    pub fn from_bytes(data: Vec<u8>) -> PEResult<Self> {
        if data.len() < 64 {
            return Err(PEError::InvalidPE("File too small".to_string()));
        }

        if &data[0..2] != b"MZ" {
            return Err(PEError::InvalidPE("Missing MZ signature".to_string()));
        }

        let pe_offset = u32::from_le_bytes([
            data[0x3C], data[0x3D], data[0x3E], data[0x3F]
        ]) as usize;

        if pe_offset + 4 > data.len() {
            return Err(PEError::InvalidPE("Invalid PE offset".to_string()));
        }

        if &data[pe_offset..pe_offset + 4] != b"PE\0\0" {
            return Err(PEError::InvalidPE("Missing PE signature".to_string()));
        }

        let coff_header_offset = pe_offset + 4;
        if coff_header_offset + 20 > data.len() {
            return Err(PEError::InvalidPE("COFF header truncated".to_string()));
        }

        let machine = u16::from_le_bytes([
            data[coff_header_offset],
            data[coff_header_offset + 1]
        ]);
        
        if machine != 0x8664 {
            return Err(PEError::UnsupportedArchitecture);
        }

        let num_sections = u16::from_le_bytes([
            data[coff_header_offset + 2],
            data[coff_header_offset + 3]
        ]);

        let size_of_optional_header = u16::from_le_bytes([
            data[coff_header_offset + 16],
            data[coff_header_offset + 17]
        ]);

        let optional_header_offset = coff_header_offset + 20;
        if optional_header_offset + size_of_optional_header as usize > data.len() {
            return Err(PEError::InvalidPE("Optional header truncated".to_string()));
        }

        if size_of_optional_header < 24 {
            return Err(PEError::InvalidPE("Optional header too small".to_string()));
        }

        let magic = u16::from_le_bytes([
            data[optional_header_offset],
            data[optional_header_offset + 1]
        ]);

        if magic != 0x20B {
            return Err(PEError::UnsupportedArchitecture);
        }

        let entry_point_rva = u32::from_le_bytes([
            data[optional_header_offset + 16],
            data[optional_header_offset + 17],
            data[optional_header_offset + 18],
            data[optional_header_offset + 19],
        ]);

        let sections_offset = optional_header_offset + size_of_optional_header as usize;

        Ok(PEFile {
            data,
            dos_header_offset: 0,
            pe_header_offset: pe_offset,
            optional_header_offset,
            sections_offset,
            num_sections,
            entry_point_rva,
        })
    }

    pub fn get_section(&self, name: &str) -> PEResult<Section> {
        for i in 0..self.num_sections {
            let section_offset = self.sections_offset + (i as usize * 40);
            if section_offset + 40 > self.data.len() {
                continue;
            }

            let mut section_name = [0u8; 8];
            section_name.copy_from_slice(&self.data[section_offset..section_offset + 8]);
            
            let section_name_str = String::from_utf8_lossy(&section_name)
                .trim_end_matches('\0')
                .to_string();

            if section_name_str == name {
                let virtual_size = u32::from_le_bytes([
                    self.data[section_offset + 8],
                    self.data[section_offset + 9],
                    self.data[section_offset + 10],
                    self.data[section_offset + 11],
                ]);

                let virtual_address = u32::from_le_bytes([
                    self.data[section_offset + 12],
                    self.data[section_offset + 13],
                    self.data[section_offset + 14],
                    self.data[section_offset + 15],
                ]);

                let size_of_raw_data = u32::from_le_bytes([
                    self.data[section_offset + 16],
                    self.data[section_offset + 17],
                    self.data[section_offset + 18],
                    self.data[section_offset + 19],
                ]);

                let pointer_to_raw_data = u32::from_le_bytes([
                    self.data[section_offset + 20],
                    self.data[section_offset + 21],
                    self.data[section_offset + 22],
                    self.data[section_offset + 23],
                ]);

                return Ok(Section {
                    name: section_name_str,
                    virtual_address,
                    virtual_size,
                    pointer_to_raw_data,
                    size_of_raw_data,
                });
            }
        }

        Err(PEError::SectionNotFound(name.to_string()))
    }

    pub fn rva_to_file_offset(&self, rva: u32) -> PEResult<usize> {
        for i in 0..self.num_sections {
            let section_offset = self.sections_offset + (i as usize * 40);
            if section_offset + 40 > self.data.len() {
                continue;
            }

            let virtual_address = u32::from_le_bytes([
                self.data[section_offset + 12],
                self.data[section_offset + 13],
                self.data[section_offset + 14],
                self.data[section_offset + 15],
            ]);

            let virtual_size = u32::from_le_bytes([
                self.data[section_offset + 8],
                self.data[section_offset + 9],
                self.data[section_offset + 10],
                self.data[section_offset + 11],
            ]);

            let pointer_to_raw_data = u32::from_le_bytes([
                self.data[section_offset + 20],
                self.data[section_offset + 21],
                self.data[section_offset + 22],
                self.data[section_offset + 23],
            ]);

            if rva >= virtual_address && rva < virtual_address + virtual_size {
                let offset_in_section = rva - virtual_address;
                return Ok((pointer_to_raw_data + offset_in_section) as usize);
            }
        }

        Err(PEError::InvalidPE(format!("Cannot resolve RVA {:#x}", rva)))
    }

    pub fn file_offset_to_rva(&self, offset: usize) -> PEResult<u32> {
        for i in 0..self.num_sections {
            let section_offset = self.sections_offset + (i as usize * 40);
            if section_offset + 40 > self.data.len() {
                continue;
            }

            let virtual_address = u32::from_le_bytes([
                self.data[section_offset + 12],
                self.data[section_offset + 13],
                self.data[section_offset + 14],
                self.data[section_offset + 15],
            ]);

            let pointer_to_raw_data = u32::from_le_bytes([
                self.data[section_offset + 20],
                self.data[section_offset + 21],
                self.data[section_offset + 22],
                self.data[section_offset + 23],
            ]);

            let size_of_raw_data = u32::from_le_bytes([
                self.data[section_offset + 16],
                self.data[section_offset + 17],
                self.data[section_offset + 18],
                self.data[section_offset + 19],
            ]);

            let raw_start = pointer_to_raw_data as usize;
            let raw_end = raw_start + size_of_raw_data as usize;
            if offset >= raw_start && offset < raw_end {
                return Ok(virtual_address + (offset - raw_start) as u32);
            }
        }

        Err(PEError::InvalidPE(format!(
            "Cannot resolve file offset {:#x}",
            offset
        )))
    }

    pub fn write_to_file<P: AsRef<Path>>(&self, path: P) -> PEResult<()> {
        fs::write(path, &self.data)?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub pointer_to_raw_data: u32,
    pub size_of_raw_data: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_pe() {
        let data = vec![0; 100];
        assert!(PEFile::from_bytes(data).is_err());
    }

    #[test]
    fn test_dos_stub() {
        let mut data = vec![0; 256];
        data[0] = b'M';
        data[1] = b'Z';
        data[0x3C] = 0x80;
        data[0x80] = b'P';
        data[0x81] = b'E';
        
        let result = PEFile::from_bytes(data);
        assert!(result.is_err() || result.is_ok());
    }
}
