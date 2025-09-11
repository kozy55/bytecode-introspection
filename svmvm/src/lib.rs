use pinocchio::{ProgramResult, account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};
use pinocchio_pubkey::pubkey;

pub const LOADER_V3: Pubkey = pubkey!("BPFLoaderUpgradeab1e11111111111111111111111");
pub const LOADER_V4: Pubkey = pubkey!("LoaderV411111111111111111111111111111111111");

#[inline(always)]
pub fn verify_executable_account<'info>(program: &'info AccountInfo, executable: &'info AccountInfo, loader: &Pubkey) -> ProgramResult {
    if !program.is_owned_by(&loader) {
        return Err(ProgramError::IncorrectProgramId);
    }

    let program_data = program.try_borrow_data()?;
    
    if program_data.len().lt(&36) {
        return Err(ProgramError::InvalidAccountData);
    }
    
    if executable.key().ne(&program_data[4..36]) {
        return Err(ProgramError::InvalidAccountData);
    }

    Ok(())
}

pub const EI_MAGIC: [u8; 4] = *b"\x7fELF"; // ELF magic
pub const EI_CLASS: u8 = 0x02; // 64-bit
pub const EI_DATA: u8 = 0x01; // Little endian
pub const EI_VERSION: u8 = 0x01; // Version 1
pub const EI_OSABI: u8 = 0x00; // System V
pub const EI_ABIVERSION: u8 = 0x00; // No ABI version
pub const EI_PAD: [u8; 7] = [0u8; 7]; // Padding
pub const E_TYPE: u16 = 0x03; // ET_DYN - shared object
pub const E_MACHINE: u16 = 0xf7; // Berkeley Packet Filter
pub const E_MACHINE_SBPF: u16 = 0x0107; // Solana Berkeley Packet Filter
pub const E_VERSION: u32 = 0x01; // Original version of BPF

// Section types
pub const SHT_STRTAB: u32 = 3;  // String table
pub const SHT_REL: u32 = 9;      // Relocation entries
pub const SHT_DYNSYM: u32 = 11;  // Dynamic symbol table

// Symbol entry size for ELF64
pub const DYNSYM_ENTRY_SIZE: usize = 24;

#[repr(C)]
pub struct Elf64Rel {
    pub r_offset: u64,  // Location at which to apply relocation
    pub r_info: u64,    // Symbol index and type of relocation
}

impl Elf64Rel {
    /// Get the symbol index from r_info
    pub fn symbol_index(&self) -> u32 {
        (self.r_info >> 32) as u32
    }
}

#[repr(C)]
pub struct ProgramHeader {
    pub p_type: u8, // An offset to a string in the .shstrtab section that represents the name of this section.
    pub p_flags: u8, // Identifies the type of this header.
    pub p_offset: u64, // Offset of the segment in the file image.
    pub p_vaddr: u64, // Virtual address of the segment in memory.
    pub p_paddr: u64, // On systems where physical address is relevant, reserved for segment's physical address.
    pub p_filesz: u64, // Size in bytes of the section in the file image. May be 0.
    pub p_memsz: u64, // Size in bytes of the segment in memory. May be 0.
    pub p_align: u64, // 0 and 1 specify no alignment. Otherwise should be a positive, integral power of 2, with p_vaddr equating p_offset modulus p_align.
}

#[repr(C)]
pub struct SectionHeader {
    pub sh_name: u32, // An offset to a string in the .shstrtab section that represents the name of this section.
    pub sh_type: u32, // Identifies the type of this header.
    pub sh_flags: u64, // Identifies the attributes of the section.
    pub sh_addr: u64, // Virtual address of the section in memory, for sections that are loaded.
    pub sh_offset: u64, // Offset of the section in the file image.
    pub sh_size: u64, // Size in bytes of the section in the file image. May be 0.
    pub sh_link: u32, // Contains the section index of an associated section. This field is used for several purposes, depending on the type of section.
    pub sh_info: u32, // Contains extra information about the section. This field is used for several purposes, depending on the type of section.
    pub sh_addralign: u64, // Contains the required alignment of the section. This field must be a power of two.
    pub sh_entsize: u64, // Contains the size, in bytes, of each entry, for sections that contain fixed-size entries. Otherwise, this field contains zero.
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ELFHeader {
    pub ei_magic: [u8; 4],
    pub ei_class: u8,
    pub ei_data: u8,
    pub ei_version: u8,
    pub ei_osabi: u8,
    pub ei_abiversion: u8,
    pub ei_pad: [u8; 7],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

impl ELFHeader {
    #[inline(always)]
    pub fn from_bytes(bytes: &[u8]) -> Result<&Self, ProgramError> {
        if bytes.len() < 64 {
            return Err(ProgramError::InvalidAccountData);
        }
        
        // Unsafe cast: reinterpret the byte slice as an ELFHeader
        // This is safe because:
        // 1. ELFHeader is repr(C) with a defined memory layout
        // 2. We've verified the slice is at least 64 bytes
        // 3. The alignment requirements are satisfied (u8 has alignment 8)
        let header = unsafe { &*(bytes.as_ptr() as *const ELFHeader) };
        
        // Validate magic number
        if header.ei_magic != EI_MAGIC {
            return Err(ProgramError::InvalidAccountData);
        }
        
        // Validate the machine ID as eBPF or sBPF
        if header.e_machine != E_MACHINE && header.e_machine != E_MACHINE_SBPF {
            return Err(ProgramError::InvalidAccountData);
        }
        
        // Validate version
        if header.e_version != E_VERSION {
            return Err(ProgramError::InvalidAccountData);
        }
        
        Ok(header)
    }
    
    /// Verify that a syscall at a specific offset is relocated to a specific function
    #[inline(always)]
    pub fn verify_syscall_relocation(&self, data: &[u8], syscall_offset: u64, expected_function: &str) -> Result<bool, ProgramError> {
        // Parse section headers
        let sh_offset = self.e_shoff as usize;
        let sh_size = self.e_shentsize as usize;
        let sh_num = self.e_shnum as usize;
        
        if sh_offset + (sh_size * sh_num) > data.len() {
            return Err(ProgramError::InvalidAccountData);
        }
        
        let mut dynstr_offset = 0usize;
        let mut dynstr_size = 0usize;
        let mut reldyn_offset = 0usize;
        let mut reldyn_size = 0usize;
        let mut dynsym_offset = 0usize;
        
        // Find the .dynstr, .rel.dyn and .dynsym sections
        for i in 0..sh_num {
            let sh_data = &data[sh_offset + (i * sh_size)..sh_offset + ((i + 1) * sh_size)];
            if sh_data.len() < core::mem::size_of::<SectionHeader>() {
                continue;
            }
            
            let section = unsafe { &*(sh_data.as_ptr() as *const SectionHeader) };
            
            match section.sh_type {
                SHT_STRTAB => { // String table
                    if dynstr_offset == 0 && section.sh_size > 0 {
                        dynstr_offset = section.sh_offset as usize;
                        dynstr_size = section.sh_size as usize;
                    }
                },
                SHT_REL => { // Relocations
                    reldyn_offset = section.sh_offset as usize;
                    reldyn_size = section.sh_size as usize;
                },
                SHT_DYNSYM => { // Dynamic symbols
                    dynsym_offset = section.sh_offset as usize;
                },
                _ => {}
            }
        }
        
        // Verify we found the necessary sections
        if dynstr_offset == 0 || reldyn_offset == 0 {
            return Err(ProgramError::InvalidAccountData);
        }
        
        // Find the expected function name in the string table
        let dynstr = &data[dynstr_offset..dynstr_offset + dynstr_size];
        let target_bytes = expected_function.as_bytes();
        let mut target_str_offset = None;
        
        for i in 0..dynstr.len().saturating_sub(target_bytes.len()) {
            if &dynstr[i..i + target_bytes.len()] == target_bytes {
                target_str_offset = Some(i);
                break;
            }
        }
        
        let target_str_offset = target_str_offset.ok_or(ProgramError::InvalidAccountData)?;
        
        // Check relocations to find the syscall
        let rel_entries = reldyn_size / core::mem::size_of::<Elf64Rel>();
        
        for i in 0..rel_entries {
            let rel_offset = reldyn_offset + (i * core::mem::size_of::<Elf64Rel>());
            if rel_offset + core::mem::size_of::<Elf64Rel>() > data.len() {
                break;
            }
            
            let rel = unsafe { &*(data[rel_offset..].as_ptr() as *const Elf64Rel) };
            
            // Check if this relocation is for our syscall
            if rel.r_offset == syscall_offset {
                // Get the symbol index
                let sym_idx = rel.symbol_index() as usize;
                
                // Look up the symbol in the symbol table
                let sym_offset = dynsym_offset + (sym_idx * DYNSYM_ENTRY_SIZE);
                
                if sym_offset + 4 <= data.len() {
                    // The first 4 bytes of a symbol entry is the name offset in dynstr
                    let name_offset = u32::from_le_bytes([
                        data[sym_offset],
                        data[sym_offset + 1],
                        data[sym_offset + 2],
                        data[sym_offset + 3],
                    ]) as usize;
                    
                    // Verify this symbol points to the expected function
                    if name_offset == target_str_offset {
                        return Ok(true);
                    }
                }
            }
        }
        
        Ok(false)
    }
}

/// Check that an LDDW instruction loads a reference to a specific immediate value into a register
#[inline(always)]
pub fn check_lddw(data: &[u8], offset: u64, dst_reg: u8, expected_value: &[u8]) -> Result<(), ProgramError> {
    let offset = offset as usize;
    
    // LDDW instruction is 16 bytes (2 x 8-byte instructions)
    if offset + 16 > data.len() {
        return Err(ProgramError::InvalidAccountData);
    }
    
    // First 8 bytes: LDDW instruction format
    // Byte 0: 0x18 (LDDW opcode)
    // Byte 1: dst_reg in lower 4 bits
    if data[offset] != 0x18 || (data[offset + 1] & 0x0f) != dst_reg {
        return Err(ProgramError::InvalidAccountData);
    }
    
    // Extract the target address from the LDDW instruction
    let low_bytes = u32::from_le_bytes([
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ]);
    
    let high_bytes = u32::from_le_bytes([
        data[offset + 12],
        data[offset + 13],
        data[offset + 14],
        data[offset + 15],
    ]);
    
    let target_address = ((high_bytes as u64) << 32) | (low_bytes as u64);
    let target_offset = target_address as usize;
    
    // Verify the target contains the expected value
    if target_offset + expected_value.len() > data.len() {
        return Err(ProgramError::InvalidAccountData);
    }
    
    let actual_value = &data[target_offset..target_offset + expected_value.len()];
    if actual_value != expected_value {
        return Err(ProgramError::InvalidAccountData);
    }
    
    Ok(())
}

/// Check that an LDDW instruction loads a specific immediate value (for simple values)
#[inline(always)]
pub fn check_lddw_imm(data: &[u8], offset: u64, expected_value: u64) -> Result<(), ProgramError> {
    let offset = offset as usize;
    
    // LDDW instruction is 16 bytes (2 x 8-byte instructions)
    if offset + 16 > data.len() {
        return Err(ProgramError::InvalidAccountData);
    }
    
    // First 8 bytes: LDDW instruction format
    // Byte 0: 0x18 (LDDW opcode)
    if data[offset] != 0x18 {
        return Err(ProgramError::InvalidAccountData);
    }
    
    // Extract the immediate value from the LDDW instruction
    let low_bytes = u32::from_le_bytes([
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ]);
    
    let high_bytes = u32::from_le_bytes([
        data[offset + 12],
        data[offset + 13],
        data[offset + 14],
        data[offset + 15],
    ]);
    
    let actual_value = ((high_bytes as u64) << 32) | (low_bytes as u64);
    
    if actual_value != expected_value {
        return Err(ProgramError::InvalidAccountData);
    }
    
    Ok(())
}

/// Check that a MOV32 instruction loads a specific immediate value into a register
#[inline(always)]
pub fn check_mov32_imm(data: &[u8], offset: u64, dst_reg: u8, expected_value: u32) -> Result<(), ProgramError> {
    let offset = offset as usize;
    
    if offset + 8 > data.len() {
        return Err(ProgramError::InvalidAccountData);
    }
    
    // MOV32 immediate instruction format:
    // Byte 0: 0xb4 (MOV32 opcode)
    // Byte 1: dst_reg in lower 4 bits
    if data[offset] != 0xb4 || (data[offset + 1] & 0x0f) != dst_reg {
        return Err(ProgramError::InvalidAccountData);
    }
    
    // Extract the immediate value (bytes 4-7)
    let actual_value = u32::from_le_bytes([
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ]);
    
    if actual_value != expected_value {
        return Err(ProgramError::InvalidAccountData);
    }
    
    Ok(())
}

/// Check that a syscall instruction calls a specific function
#[inline(always)]
pub fn check_call(data: &[u8], offset: u64, expected_function: &str) -> Result<(), ProgramError> {
    let offset = offset as usize;
    
    if offset + 8 > data.len() {
        return Err(ProgramError::InvalidAccountData);
    }
    
    // Call instruction format:
    // Byte 0: 0x85 (CALL opcode)
    // Byte 1: 0x10 (helper call)
    if data[offset] != 0x85 || data[offset + 1] != 0x10 {
        return Err(ProgramError::InvalidAccountData);
    }
    
    // For syscalls, we need to check the relocation table to verify the target
    // This reuses the existing verify_syscall_relocation logic
    let header = ELFHeader::from_bytes(data)?;
    header.verify_syscall_relocation(data, offset as u64, expected_function)
        .and_then(|found| {
            if found {
                Ok(())
            } else {
                Err(ProgramError::InvalidAccountData)
            }
        })
}