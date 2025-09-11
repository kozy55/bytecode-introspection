use pinocchio::ProgramResult;

use crate::elf::{ELFHeader, check_lddw_imm, check_mov32_imm, check_call, check_lddw_imm_u64};

/// Only allows us to CPI into a program that provably greets us with a "gm" first.
pub fn gm(data: &[u8]) -> ProgramResult {
    // Parse and validate the ELF header
    let header = ELFHeader::from_bytes(data)?;

    // Check middleware
    check_lddw_imm(data, header.e_entry, 1, b"gm")?;
    check_mov32_imm(data, header.e_entry+16, 2, 2)?;
    check_call(data, header.e_entry+24, "sol_log_")?;
    check_lddw_imm_u64(data, header.e_entry+32, 0x400000000)?;

    Ok(())
}