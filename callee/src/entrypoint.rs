#[macro_export]
macro_rules! named_entrypoint {
    ( $name:ident, $process_instruction:expr ) => {
        $crate::named_entrypoint!($name, $process_instruction, { pinocchio::MAX_TX_ACCOUNTS });
    };
    ( $name:ident, $process_instruction:expr, $maximum:expr ) => {
        /// Program entrypoint.
        #[no_mangle]
        pub unsafe extern "C" fn $name(input: *mut u8) -> u64 {
            const UNINIT: core::mem::MaybeUninit<pinocchio::account_info::AccountInfo> =
                core::mem::MaybeUninit::<pinocchio::account_info::AccountInfo>::uninit();
            // Create an array of uninitialized account infos.
            let mut accounts = [UNINIT; $maximum];

            let (program_id, count, instruction_data) =
                pinocchio::entrypoint::deserialize::<$maximum>(input, &mut accounts);

            // Call the program's entrypoint passing `count` account infos; we know that
            // they are initialized so we cast the pointer to a slice of `[AccountInfo]`.
            match $process_instruction(
                &program_id,
                core::slice::from_raw_parts(accounts.as_ptr() as _, count),
                &instruction_data,
            ) {
                Ok(()) => pinocchio::SUCCESS,
                Err(error) => error.into(),
            }
        }
    };
}