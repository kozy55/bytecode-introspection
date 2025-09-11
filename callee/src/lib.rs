#![cfg_attr(target_os = "solana", no_std, feature(asm_experimental_arch))]
use pinocchio::{ProgramResult, account_info::AccountInfo, no_allocator, nostd_panic_handler, program_error::ProgramError, pubkey::Pubkey, syscalls::sol_get_stack_height};
use pinocchio_system::instructions::Transfer;

mod entrypoint;

nostd_panic_handler!();
no_allocator!();

pub static GM: [u8;2] = *b"gm";

#[no_mangle]
pub unsafe extern "C" fn entrypoint(input: *mut u8) {
    #[cfg(target_os = "solana")]
    core::arch::asm!(
        "lddw r1, {}",
        "mov32 r2, 0x0002",
        "call sol_log_",
        "lddw r1, 0x400000000", // Reset input region pointer
        sym GM
    );
    let res = e(input);
    #[cfg(target_os = "solana")]
    unsafe {
        core::arch::asm!(
            "mov64 r0, {}",
            "exit",
            in(reg) res
        )
    }
}

named_entrypoint!(e, process_instruction);

#[inline(always)]
pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let [from, to, _system_program] = accounts else {
        return Err(ProgramError::InvalidAccountData)
    };
    let lamports = u64::from_le_bytes(instruction_data.try_into().map_err(|_| ProgramError::InvalidInstructionData)?);

    Transfer {
        from,
        to,
        lamports,
    }.invoke()?;

    // Enforce that we are in a CPI!
    #[cfg(target_os = "solana")]
    if unsafe { sol_get_stack_height() } == 1 {
        return Err(ProgramError::InvalidArgument);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use mollusk_svm::{Mollusk, program::keyed_account_for_system_program, result::Check};
    use solana_sdk::{account::Account, instruction::{AccountMeta, Instruction}, program_error::ProgramError, pubkey::Pubkey};

    #[test]
    fn test() {
        let program_id = Pubkey::new_from_array([0x02;32]);

        let from = Pubkey::new_unique();
        let to = Pubkey::new_unique();
        let (system_program, system_program_account) = keyed_account_for_system_program();
        
        let instruction = Instruction::new_with_bytes(
            program_id,
            &1337u64.to_le_bytes(),
            vec![
                AccountMeta::new(from, true),
                AccountMeta::new(to, false),
                AccountMeta::new_readonly(system_program, false),
            ]
        );

        let mollusk = Mollusk::new(&program_id, "target/deploy/callee");

        mollusk.process_and_validate_instruction(
            &instruction,
            &[
                (
                    from,
                    Account::new(1_000_000_000, 0, &Pubkey::default())
                ),
                (
                    to,
                    Account::new(0, 0, &Pubkey::default())
                ),
                (
                    system_program,
                    system_program_account
                ),
            ],
            &[Check::err(ProgramError::InvalidArgument)]
        );
    }
}