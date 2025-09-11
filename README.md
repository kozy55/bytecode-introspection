# Bytecode Introspection

This workspace demonstrates bytecode introspection of a callee program by a caller program, enabling the caller to verify the execution of a specific bytecode middleware at the entrypoint of the callee before invoking it via CPI. In this case, we will only allow a program to be invoked by the caller program if it first verifiably greets us with a friendly "gm". If you learn assembly, and disrespect the compiler, this can be extrapolated as far as your imagination allows.

## Architecture

The workspace contains two Solana programs:

### 1. **Callee Program** (`callee/`)
A simple program that:
- Logs "gm" using inline assembly at the entrypoint
- Accepts transfer instructions via CPI
- Uses `sol_get_stack_height()` to verify it's being called through CPI (not directly)
- Contains the "gm" marker in its binary that can be introspected
- Transfers lamports between accounts using the System Program

### 2. **Caller Program** (`caller/`)
A program that demonstrates bytecode introspection by:
- Validating the target program's account structure
- Verifying the program is owned by the BPF Loader Upgradeable
- Extracting and validating the programdata address
- Reading the executable ELF binary directly
- Checking for the "gm" marker in the ELF (at byte offset 45+)
- Only invoking the program after validation passes

## Key Concepts

### Bytecode Introspection
The caller program demonstrates how to introspect another program's executable before calling it:

1. **Program Account Validation**: Verifies the program account is properly owned and structured
2. **Executable Data Access**: Reads the actual ELF binary from the programdata account
3. **Binary Analysis**: Examines the ELF content for specific patterns or markers (in this case, "gm")
4. **Middleware Guard**: Acts as a security layer that validates programs before execution

### Stack Height Check
The callee uses `sol_get_stack_height()` to ensure it's only called via CPI, preventing direct invocations. This is a security measure to ensure the program operates in the expected context.

## Building

Build both programs for Solana BPF:

```bash
cargo build-sbf
```

## Testing

Run tests with Mollusk (Solana VM simulator):

```bash
cargo test-sbf
```

This will test both programs using Mollusk, which simulates the Solana runtime environment locally.

## Test Coverage

- **Callee Tests**: Verify that direct invocations are rejected (must be called via CPI)
- **Caller Tests**: Test the full CPI introspection flow, including:
  - Loading the callee program's ELF binary
  - Validating the program structure
  - Checking for the "gm" marker in the binary
  - Successfully executing the CPI after validation

## Security Implications

This pattern demonstrates how programs can implement additional security layers by:
- Inspecting other programs before interacting with them
- Verifying specific binary patterns or signatures
- Creating middleware-like validation layers in a decentralized environment
- Preventing unauthorized direct invocations

## Use Cases

- **Allowlist Systems**: Only invoke programs that contain specific markers
- **Version Checking**: Verify program versions before interaction
- **Security Auditing**: Inspect program binaries for known patterns
- **Middleware Implementation**: Create validation layers between programs