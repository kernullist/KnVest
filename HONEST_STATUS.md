# Honest Status — L1–L7 Architecture Status

## What Works & Is Verified (`cargo test` — 262 Tests Passing)

### 1. PE32+ Infrastructure & Sidecar Metadata (`src/pe/parser.rs`, `src/pe/packer.rs`)
- Parses PE32+ (`x86_64`) executables (MinGW/MSVC), preserving COFF symbols, string tables, and overlays.
- Injects `.knvest` section with proper section/file alignment and entry-point redirection.
- **L7 Trailer Scrubbing & `.knvmap` Sidecar**:
  - `--strip-meta` (`scrub_embedded_metadata_in_pe`) scrubs plaintext `KNV4`, `KNV5`, `KNV6`, `KNV7`, and `VMBC` headers from `.knvest` using a seed-derived SplitMix64 stream while preserving runtime-referenced KNV6 transition tables.
  - Emits an out-of-band `KNVM` (`.knvmap`) sidecar file so `knvest ir` can still disassemble stripped binaries losslessly.
  - All Win32/PEB string literals (`kernel32.dll`, `GetProcAddress`, `GetStdHandle`, `WriteFile`, `ExitProcess`) inside `vm_stub` are XOR-encoded with a seed-derived key and decoded at runtime.

### 2. x64 Lifter & 32-Register VM Frame Model (`src/pe/lifter.rs`, `src/vm/machine.rs`)
- **32 Virtual Registers (`r0..r31`) & Scratch Isolation**:
  - `r0..r9`: x64 general-purpose register mapping (`rax`, `rcx`, `rdx`, `rbx`, `rsp`, `rbp`, `rsi`, `rdi`, `r8`, `r9`).
  - `r10..r13` and `r16..r31`: 20 dedicated local `[rbp ± disp]` stack spill slots.
  - `r14` and `r15`: strictly isolated lifter/MBA scratch registers (`alloc_stack_spill_reg` never assigns locals to `r14` or `r15`).
- **Instruction Coverage (L1–L7)**:
  - Data movement & addressing: `mov`, `movzx`, `movsxd`, `cdqe`, general `lea` (`[base + disp]`, `[base + index*scale + disp]`, `[rip + disp]`), general pointer memory load/store (`[reg + disp]`), `push`, `pop`.
  - Arithmetic, bitwise, unary & shift: `add`, `sub`, `imul`, `idiv`/`div`, `inc`, `dec`, `and`, `or`, `xor`, `not`, `neg`, `shl`, `shr`, `sar`.
  - Comparisons & all 12 conditional branches: `cmp` (64-bit & 32-bit `cmp32`), `test reg, reg`, `test reg, imm`, `je`, `jne`, `jg`, `jl`, `jge`, `jle`, `ja`, `jae`, `jb`, `jbe`, `js`, `jns`.
  - Sample-specific hardcoded heuristics (`force_nested_product_single_digit_path`) have been completely removed; all 8 MinGW sample programs lift and pass via genuine instruction semantics.
  - `LiftPolicy::Strict` (`validate_strict_lift`) detects and reports any unlifted `X64InstrKind::Unknown` instruction.

### 3. Standalone x64 Interpreter Stub & Win64 ABI Bridge (`src/pe/vm_stub.rs`)
- Resolves `kernel32.dll` via PEB `InMemoryOrderModuleList` and locates `GetProcAddress`, `GetStdHandle`, `WriteFile`, and `ExitProcess`.
- **Universal Win64 IAT `NativeCall` Bridge (`nc_iat`)**:
  - Supports stdio pointer fixups (bit 31), legacy single-byte `putchar` (default), and generic 4-argument Win64 ABI calls (`NATIVE_CALL_IAT_GENERIC_FLAG`, bit 30: `rcx=r0, rdx=r1, r8=r2, r9=r3` + 32-byte shadow space).
  - Captures the native Win64 return value `rax` back into VM `r0` (`mov [rbp-0x80], rax`) before restoring caller-saved VM slots.
- **Caller-Return Mode (`StubExitMode::ReturnToCaller`)**:
  - Supports unwinding the interpreter frame and returning the VM exit register in `rax` via `leave; ret` instead of terminating the process via `ExitProcess`.

### 4. Multi-Layer Obfuscation & Bytecode Diversification (`L4`–`L7`)
- **L4a/L4b/L5a/L6**: Seeded opcode wire permutation and polymorphic x64 handler variants (`Add`, `Sub`, `Xor`, `And`, `Mul`, `Move`).
- **L4c**: Table (`--dispatch table`) and direct-threaded (`--dispatch threaded`) dispatch.
- **L4d**: Partial basic-block virtualization (`--partial`) with native sled execution and frame spill synchronization.
- **L4e/L5d**: Per-CFG-edge `(pred_bb, succ_bb) -> tx_id` 256-entry transition-keyed dispatch tables (`KNV6`).
- **L4f/L5b/L6**: Depth-1 and Depth-2 Mixed Boolean-Arithmetic (`--mba 1|2`) and 64-bit constant unfolding.
- **L5c/L7**: Per-opcode post-wire dead-byte padding (`KNV7`), rolling SplitMix64 keystream encryption (`BytecodeCipher`), and extended register slot permutation.
- **L5e/L5f**: Dual virtual ISA (`--isa reg|stack`) and two-layer nested VM (`--nested`).

## Remaining Scope Boundaries (By Design)
- Floating-point / XMM / AVX instructions, SEH/pdata unwinding tables, TLS callbacks, and multi-threaded synchronization primitives remain outside the scope of this educational protector.
