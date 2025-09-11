use pinocchio::{ProgramResult, account_info::AccountInfo, cpi::invoke, entrypoint, instruction::{AccountMeta, Instruction}, program_error::ProgramError, pubkey::Pubkey};
use svmvm::{LOADER_V3, verify_executable_account};

mod middleware_guard;

entrypoint!(process_instruction);

fn process_instruction(
    _program_id: &Pubkey,      // Public key of the account the program was loaded into
    accounts: &[AccountInfo], // All accounts required to process the instruction
    _instruction_data: &[u8],  // Serialized instruction-specific data
) -> ProgramResult {
    let [program, executable, from, to, system_program] = accounts else {
        return Err(ProgramError::InvalidAccountData);
    };

    verify_executable_account(program, executable, &LOADER_V3)?;
    
    let executable_data = &executable.try_borrow_data()?[45..];
    
    middleware_guard::gm(executable_data)?;

    invoke::<3>(
        &Instruction {
            program_id: program.key(),
            data: &1337u64.to_le_bytes(),
            accounts: &[
                AccountMeta {
                    pubkey: from.key(),
                    is_writable: true,
                    is_signer: true
                },
                AccountMeta {
                    pubkey: to.key(),
                    is_writable: true,
                    is_signer: false
                },
                AccountMeta {
                    pubkey: &Pubkey::default(),
                    is_writable: false,
                    is_signer: false
                },
            ],
        }, &[
            from,
            to,
            system_program
        ]
    )
}

#[cfg(test)]
mod tests {
    use mollusk_svm::{Mollusk, program::{keyed_account_for_system_program, loader_keys}, result::Check};
    use solana_sdk::{account::Account, instruction::{AccountMeta, Instruction}, pubkey::Pubkey};
    use solana_sdk::pubkey;

    const CALLEE: Pubkey = pubkey!("Ca11ee1111111111111111111111111111111111111");
    const EXECUTABLE: Pubkey = pubkey!("Gvto1iiJBKd5jNVfwHd7VUwTN1tZzgrEBMJ8AupKu8TX");

    #[test]
    fn test() {
        let program_id = Pubkey::new_from_array([0x02;32]);

        let mut mollusk = Mollusk::new(&program_id, "target/deploy/caller");
        
        // Load the callee ELF binary at compile time
        let callee_elf = include_bytes!("../../callee/target/deploy/callee.so");
        mollusk.add_program_with_elf_and_loader(&CALLEE, callee_elf, &loader_keys::LOADER_V3);

        let from = Pubkey::new_unique();
        let to = Pubkey::new_unique();
        let (system_program, system_program_account) = keyed_account_for_system_program();
        let (callee, callee_account) = (CALLEE, mollusk_svm::program::create_program_account_loader_v3(&CALLEE));
        // Load the executable account data (programdata account)
        let mut executable_data = vec![0u8; 45];
        executable_data[0] = 0x03;
        executable_data.extend_from_slice(callee_elf);
        let mut executable_account = Account::new(1_000_000_000, executable_data.len(), &loader_keys::LOADER_V3);
        executable_account.data = executable_data;
        let (executable, executable_account) = (EXECUTABLE, executable_account);

        let instruction = Instruction::new_with_bytes(
            program_id,
            &1337u64.to_le_bytes(),
            vec![
                AccountMeta::new_readonly(callee, false),
                AccountMeta::new_readonly(executable, true),
                AccountMeta::new(from, true),
                AccountMeta::new(to, false),
                AccountMeta::new_readonly(system_program, false),
            ]
        );

        mollusk.process_and_validate_instruction(
            &instruction,
            &[
                (
                    callee,
                    callee_account
                ),
                (
                    executable,
                    executable_account
                ),
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
            &[Check::success()]
        );
    }
}