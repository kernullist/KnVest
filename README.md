# KnVest

Educational x64 VM protector + IR viewer for Windows PE64 (`PE32+`) binaries.

## What It Is

KnVest is an educational and research tool that demonstrates layered VM-based code virtualization and bytecode diversification for Windows x86-64 executables. It provides:

1. A dual-mode virtual machine (`reg` 3-operand register ISA and `stack` push/pop ALU ISA) with 32 virtual registers (`r0..r31`, with `r13` reserved for virt-ISA sub-split, `r14..r15` strictly isolated as lifter/MBA scratch registers, and `r10..r12`, `r16..r31` providing 19 dedicated local spill slots), call stack, data stack, and x64 flags (`ZF`/`SF`/`CF`/`OF`)
2. A PE64 packer that decodes x64 functions via [`iced-x86`](https://github.com/icedland/iced), lifts them into custom VM bytecode, and injects a standalone in-process x64 interpreter stub into a `.knvest` section (with optional `--strip-meta` trailer scrubbing and `.knvmap` sidecar emission)
3. An IR disassembler (`knvest ir`) that reconstructs per-seed wire mappings, transition tables, layout padding, MBA headers, and nested-VM tables from either embedded metadata or an out-of-band `.knvmap` sidecar to pretty-print VM bytecode

**Language:** Rust  
**Target:** Windows x86-64 PE (`PE32+`)

## What It Is NOT

This is an educational project, not a commercial protector. It does NOT include:

- Anti-debug, anti-VM, or kernel-mode drivers
- Full x64 ISA or packed SIMD coverage (L8 adds scalar SSE/SSE2 only: `movss`/`movsd`/`movq`/`movd`, `movaps`/`movups`, scalar add/sub/mul/div, `ucomi`/`comi`, `cvtsi2sd`/`cvtsi2ss`, `cvttsd2si`/`cvttss2si`, `cvtss2sd`/`cvtsd2ss`, `xorps`/`xorpd`)
- Decompilation or LLVM/MLIR bitcode lifting

## Architecture & Protection Layers (L1 – L13)

| Layer | Feature | Trailer / Module | Summary |
|-------|---------|------------------|---------|
| **L1–L3** | PE64 parsing, CFG collection, IAT `native_call`, standalone x64 stub | `parser.rs`, `cfg.rs`, `imports.rs`, `lifter.rs`, `vm_stub.rs` | BFS over direct `call rel32` targets in `.text`; `call [rip+IAT]` resolved via PE import directory and invoked with Win64 ABI (`rcx`/`rdx`/`r8`/`r9` + shadow space + `rax -> r0` return capture) |
| **L4a** | Seeded wire-byte permutation & handler order shuffle | `opcode_map.rs` (`KNV4` v1–v5) | Permutes the 21 canonical opcode wire bytes across `0x00..=0xFF` (`0xFD` reserved for `SetBlockMap` meta-wire) and shuffles native handler emission order in `.knvest` |
| **L4b / L5a / L6 / L7** | Handler polymorphism (n:1 native bodies) | `opcode_map.rs`, `vm_stub.rs`, `virt_isa.rs` | Seed-selected semantically equivalent x64 handler bodies for `Add` (3), `Sub` (2), `Xor` (2), `And` (2), `Mul` (2), `Move` (2), `LoadImm` (2), and `Cmp` (2), plus virtual-ISA `sub` split (`neg` + `add`) |
| **L4c** | Table vs. threaded dispatch | `dispatch.rs`, `threaded.rs` | `--dispatch table` (256-entry handler table) or `--dispatch threaded` (inline `rel32` handler offsets after each wire byte, direct handler-to-handler tail jump) |
| **L4d** | Partial BB virtualization & native bail-out | `partial.rs` (`KNV5`) | `--partial` keeps selected straight-line basic blocks native via `run_native` / `bail_native` sleds while synchronizing VM spill registers with the native `[rbp±disp]` frame |
| **L4e / L5d** | Transition-keyed per-edge opcode maps | `block_map.rs` (`KNV6` v1–v3) | Per-CFG-edge `(pred_bb, succ_bb) -> tx_id` 256-entry dispatch tables switched at basic-block boundaries and edge landing pads via `[0xFD][tx_id: u16]` (`set_block_map`) |
| **L4f / L5b / L6 / L7** | Mixed Boolean-Arithmetic (MBA), constant unfolding & opaque predicates | `mba.rs` | `--mba 0\|1\|2` rewrites `Add`, `Sub`, `Xor`, `And`, and synthesized `Or` (`a \| b = (a ^ b) + (a & b)`) into multi-instruction boolean-arithmetic sequences; `--mba 2` automatically unfolds `LoadImm` constants (`emit_load_imm_unfolded`) and injects seed-derived opaque branch guards (`emit_opaque_branch_guard`) |
| **L5c** | Bytecode layout diversification | `layout.rs`, `layout_pass.rs` (`KNV7`) | Inserts 0–3 bytes of seed-derived post-wire dead padding (`0xCC`) per opcode and relocates all branch, call, and string-pool offsets |
| **L5e** | Dual virtual ISA (`reg` / `stack`) | `isa_mode.rs` | `--isa reg` (default 3-operand register ALU) or `--isa stack` (stack-machine ALU popping operands and pushing results on the VM data stack) |
| **L5f** | Nested VM (two-layer dispatch) | `nested_vm.rs` (`KNV4` v5, `KNV6` v3) | `--nested` separates **outer decode** (per-transition `outer_decode[256]` wire translation) from **inner execute** (`dispatch_inner` handler table) |
| **L6** | Extended x64 lifter & branch semantics | `lifter.rs`, `cfg.rs`, `machine.rs`, `vm_stub.rs` | Lifts bitwise/unary/shift ops (`AND`, `OR`, `XOR`, `NOT`, `NEG`, `SHL`, `TEST reg, imm`) and register extension moves (`MOVZX`, `MOVSX`, `MOVSXD`, `CDQE`, plus 32-bit zero-extension `emit_u32_zext`) across register, immediate, and `[rbp±disp]` stack slots, and supports signed, unsigned, and sign conditional jumps (`JE`, `JNE`, `JG`, `JL`, `JGE`, `JLE`, `JA`, `JAE`, `JB`, `JBE`, `JS`, `JNS`) |
| **L7** | Metadata scrubbing / `.knvmap` sidecar, 32-reg frame & scratch isolation, universal Win64 ABI & caller-return stub, rolling stream cipher | `packer.rs` (`KNVM`), `lifter.rs`, `vm_stub.rs`, `layout.rs` | `--strip-meta` and `--sidecar <PATH>` scrub `KNV4`..`KNV7` & every `VMBC` marker and emit `.knvmap`; XOR-encodes all PEB/API strings in `vm_stub` and immediately zero-wipes the stack buffer after `GetProcAddress`; expands VM to 32 registers (`r13` virt-ISA split scratch, `r14..r15` isolated for MBA/lifter, 19 local slots `r10..r12` & `r16..r31`); adds `shr`, `sar`, `div`/`idiv` (`rdx:rax`, including `[base+disp]` with no index), `cdq`/`cqo`, scaled `lea`, general pointer `[reg+disp]` load/store, partial byte/word `[rbp+disp]` moves, and `--strict` (`validate_strict_lift`); supports generic Win64 IAT calls (`rcx, rdx, r8, r9` + 5th/6th stack args `[rsp+0x20]=r4`, `[rsp+0x28]=r5` + `rax -> r0`) and `--return-mode` (`StubExitMode::ReturnToCaller`); integrates `BytecodeCipher` rolling SplitMix64 keystream & register slot permutation (`VirtualMachine::with_cipher_decrypted`, `alloc_stack_spill_reg_seeded`) |
| **L8** | Fetch-time rolling wire decrypt, `jmp reg` / switch tables, scalar XMM, multi-function packing | `l8.rs`, `vm_stub.rs`, `lifter.rs`, `cfg.rs`, `machine.rs`, `packer.rs`, `ir` | `--rolling-cipher` XORs each instruction-start wire with `rolling_wire_mask(seed, offset)` (`KNV4` v5 flag `0x02`) and decrypts it in the three native dispatch loops, the Rust VM, and `knvest ir`. `jmp reg` and compiler switch tables lift to a `Cmp`/`JmpIf` chain plus `native_call` `jmp_reg`. Scalar SSE rides on `native_call` immediates (`xmm_addsd`, `ucomiss`, `comiss`, `movq`, `movd`, `cvtsi2ss`, `cvtss2sd`, …) with a 16-slot XMM file at `[rbp-0x4B0]`. Repeated `--rva` / `--rvas` pack several functions: each gets a stub and bytecode entry, non-primary stubs `leave; ret`, and a 5-byte `E9` trampoline is written only when more than one RVA is packed. `.knvmap` stores every function image (a single-function file stays v1-compatible) and `knvest ir` prints the extras. `comiss`/`comisd` set PF when unordered and signal invalid on any NaN; `ucomiss`/`ucomisd` signal only on SNaN. A populated block map does not invent a wire alphabet for an unknown transition |
| **L9** | Per-slot register-file XOR and a mul+add superoperator | `l9.rs`, `vm_stub.rs`, `machine.rs`, `packer.rs`, `ir` | `--reg-encrypt` stores each virtual register as `plaintext XOR reg_slot_key(seed, slot)` (`KNV4` v5 flag `0x04`). The stub keeps the 32 keys beside the bytecode image; the prologue copies them into the register file (a logical zero is the key itself) and each handler decodes a slot only for the instruction that reads or writes it. The VM data stack and guest memory stay plaintext. `--superops` fuses an adjacent register-ISA `mul` + `add` into one `native_call` (`madd`, tag `0x7_0000_0000`, `dst = a * b + c`) before layout padding, when the product is overwritten by the add or is dead before the next branch, call, or native micro-op, and when nothing jumps onto the `add`. Stack ISA bytecode is left unchanged. Both flags default off, and that stub is byte-identical to the L8 stub. The canonical opcode count stays 21 |
| **L10** | Position-keyed qword immediate cipher | `l10.rs`, `vm_stub.rs`, `machine.rs`, `packer.rs`, `ir` | `--imm-cipher` XORs each 8-byte immediate with `imm_cipher_mask(seed, offset)` (`KNV4` v5 flag `0x08`). The offset is the bytecode index of that qword: `load_imm` / `load_str` / `jmp_if` constants and targets, `jmp` / `call` / `native_call` immediates, and both `run_native` / `bail_native` qwords. The `jmp_if` condition byte, threaded `rel32` handler targets, and layout padding stay plaintext. Handlers decrypt into a register and do not write the image back. The pass runs after layout diversification and threaded embedding, and after the L8 wire mask when both flags are on. It defaults off, and that stub is byte-identical to the L9 stub. The canonical opcode count stays 21 |
| **L11** | Position-keyed register-index mask | `l11.rs`, `vm_stub.rs`, `machine.rs`, `packer.rs`, `ir` | `--reg-index` XORs each register-index operand byte with `reg_index_mask(seed, offset)` (`KNV4` v5 flag `0x10`). The mask is the L8 32-bit mix with a separate salt, so the same slot is a different byte at each offset. Stack ALU masks only the destination byte. The `jmp_if` condition, qword immediates, threaded `rel32` targets, and layout padding stay as stored. Handlers unmask the loaded index before they use it. The pass runs after the L10 immediate cipher. It defaults off, and that stub is byte-identical to the L10 stub. The canonical opcode count stays 21 |
| **L12** | Per-depth call-stack return cipher | `l12.rs`, `vm_stub.rs`, `machine.rs`, `packer.rs` | `--ret-encrypt` XORs each call-stack return record with `call_slot_mask(seed, depth)` (`KNV4` v5 flag `0x20`). Depth is the slot index at the `call` store and again at the `ret` load, so a nested call uses the next slot. The record holds the return bytecode index and, on a block-map transition, the caller block id. `ret` restores that qword before it splits the index and the caller block. The VM data stack and register `push`/`pop` stay plaintext. The flag changes no bytecode image. It defaults off, and that stub is byte-identical to the L11 stub. The canonical opcode count stays 21 |
| **L13** | Per-depth data-stack cipher | `l13.rs`, `vm_stub.rs`, `machine.rs`, `packer.rs` | `--stack-encrypt` XORs each data-stack qword with `data_slot_mask(seed, depth)` (`KNV4` v5 flag `0x40`). Depth is the slot index at the store and again at the load. Stack-ISA `push`, `pop`, and ALU use that stack. The stub applies the same mask on every data-stack store and load, including register-ISA `push`/`pop`, which the stub keeps on the data stack. Register-ISA `push`/`pop` in the reference VM stay on the call stack as plaintext. Call-stack return records stay on the L12 mask. The flag changes no bytecode image. It defaults off, and that stub is byte-identical to the L12 stub. The canonical opcode count stays 21 |

## Build

```bash
cargo build --release
```

The binary will be at `target/release/knvest` (or `knvest.exe` on Windows).

## Usage

### Pack an Executable

Virtualize the detected `main` function (and CFG-reachable callees in `.text`) and write a new PE whose entry point starts at the `.knvest` VM interpreter stub (`0x55` = `push rbp`):

```bash
knvest pack input.exe -o output.exe
```

#### CLI Options (`knvest pack`)

| Option | Default | Description |
|--------|---------|-------------|
| `-o, --output <FILE>` | *(required)* | Output packed PE64 executable path |
| `--rva <HEX>` | auto-detect `main` | Function RVA to protect. Repeat the flag or pass a comma-separated list (`--rva 0x1000,0x1030`) |
| `--rvas <HEX>` | *(none)* | Comma-separated RVAs, combined with `--rva` |
| `--rolling-cipher` | `false` | L8: encrypt each bytecode wire with a position/seed key and decrypt it at fetch time |
| `--reg-encrypt` | `false` | L9: XOR-encode each virtual register slot with a per-slot pack-time key |
| `--superops` | `false` | L9: fuse adjacent register-ISA `mul`+`add` into one `madd` `native_call` |
| `--imm-cipher` | `false` | L10: XOR each qword immediate with a position key; handlers decrypt it in a register |
| `--reg-index` | `false` | L11: XOR each register-index byte with a position key; handlers decrypt it before use |
| `--ret-encrypt` | `false` | L12: XOR each call-stack return record with a per-depth key |
| `--stack-encrypt` | `false` | L13: XOR each data-stack qword with a per-depth key |
| `--seed <SEED>` | random per pack | 64-bit seed (hex `0x...` or decimal) controlling wire permutation, handler variants, layout padding, MBA catalog selection, and nested tables |
| `--dispatch <MODE>` | `table` | Dispatch mode: `table` (256-entry handler table) or `threaded` (inline `rel32` handler targets) |
| `--partial` | `false` | Enable L4d partial BB virtualization (`run_native` / `bail_native` sleds) |
| `--mba [LEVEL]` | `0` (`off`) | MBA substitution depth: `0`/`off`, `1`/`on` (single catalog rewrite), or `2` (nested depth-limited rewrite) |
| `--isa <MODE>` | `reg` | Virtual ISA operand model: `reg` (3-operand registers) or `stack` (push/pop stack ALU) |
| `--nested` | `false` | Enable L5f nested VM (outer decode + inner execute; requires `--dispatch table`) |
| `--strip-meta` | `false` | L7: Scrub embedded `KNV4`..`KNV7` headers and every `VMBC` marker from `.knvest` and emit a `.knvmap` sidecar. The sidecar records every packed function, and `knvest ir` prints the extras |
| `--sidecar <PATH>` | `<output>.knvmap` | L7: Custom path for the `.knvmap` sidecar file (supported on both `knvest pack` and `knvest ir`) |
| `--strict` | `false` | L7: Strict lifting mode — fail if any non-prologue/epilogue instruction cannot be virtualized without `BailNative` |
| `--return-mode` | `false` | L7: Function-level VM exit mode (`StubExitMode::ReturnToCaller`) — return to caller via `leave; ret` instead of calling `ExitProcess` |

Example invocations:

```bash
# Reproducible seed + threaded dispatch
knvest pack input.exe -o output.exe --seed 0xdeadbeef --dispatch threaded

# Depth-2 MBA + stack-machine virtual ISA
knvest pack input.exe -o output.exe --seed 0x1337c0de --mba 2 --isa stack

# Nested VM (outer decode + inner execute) with partial virtualization
knvest pack input.exe -o output.exe --seed 0xfeedface --nested --partial

# L8: two functions, rolling wire cipher, caller-return on the non-primary stub
knvest pack input.exe -o output.exe --seed 0x4c380001 --rva 0x1000,0x1030 --rolling-cipher

# L9: per-slot register encoding and mul+add fusion
knvest pack input.exe -o output.exe --seed 0x4c390001 --reg-encrypt --superops

# L10: position-keyed immediate cipher, with the L8 wire mask
knvest pack input.exe -o output.exe --seed 0x4c310001 --imm-cipher --rolling-cipher

# L11: position-keyed register-index bytes
knvest pack input.exe -o output.exe --seed 0x4c310001 --reg-index

# L12: per-depth call-stack return records
knvest pack input.exe -o output.exe --seed 0x4c310001 --ret-encrypt

# L13: per-depth data-stack qwords
knvest pack input.exe -o output.exe --seed 0x4c310001 --stack-encrypt --isa stack
```

### View IR

Pretty-print the VM metadata headers and disassembled bytecode from a packed executable:

```bash
knvest ir output.exe
```

Example output:

```text
L4c dispatch=table | L4a seed=0xdeadbeef
L4e/L5d block_map: blocks=4 transitions=5 ...
L5c layout: pad_counts=[...]
L5a virt_isa: add(v1) sub(v0) xor(v1) and(v0) mul(v1) move(v0) ...
L5e isa=reg
Address  | Opcode       | Operands
---------+--------------+---------
00000000 | set_block_map| tx#0
00000003 | push         | r5
00000005 | move         | r5, r4
...
00000024 | native_call  | 0x100000030
0000002d | load_imm     | r0, 0x0
00000036 | exit         | r0
```

`native_call` values `0x100000000 | iat_rva` invoke imported Win32/CRT functions through the PE IAT using the Win64 calling convention. Legacy helpers remain supported (`1` = `WriteFile` string, `2` = integer print, `3` = `putchar`).

## Runtime & Trailer Metadata

The `.knvest` section embeds the x64 interpreter stub, string pool, native sleds (when `--partial` is active), metadata trailers, and the `VMBC` bytecode payload:

- **`KNV4` (v1–v5)**: Pack seed, dispatch mode, MBA level, `IsaMode` (`reg`/`stack`), `nested_vm` flag, and the 21-byte canonical wire table (`Nop`, `LoadImm`, `Move`, `Add`, `Sub`, `Mul`, `Cmp`, `Jmp`, `JmpIf`, `Call`, `Ret`, `NativeCall`, `Push`, `Pop`, `LoadByte`, `Cmp32`, `And`, `Xor`, `RunNative`, `BailNative`, `Exit`).
- **`KNV5`**: L4d partial virtualization plan and native sled RVA mappings.
- **`KNV6` (v1–v3)**: L4e/L5d transition-keyed opcode maps and (in v3) per-transition `outer_decode[256]` tables for L5f `--nested`.
- **`KNV7`**: L5c per-opcode post-wire dead-byte padding (`0..=3` bytes) table.

### Handler Polymorphism (`L4b` / `L5a` / `L6`)

Logical opcodes with multiple native x64 handler bodies selected deterministically from `--seed`:

| Logical Opcode | Variants | Summary of Native x64 Implementations |
|----------------|----------|---------------------------------------|
| `add` | 3 | `add rax, [src2]`, `lea rax, [rax+rbx]`, or direct destination store + memory `add` |
| `sub` | 2 | `sub rax, [src2]` vs. `not rbx; inc rbx; add rax, rbx` (two's-complement negation) |
| `xor` | 2 | Direct `xor rax, [src2]` vs. register-staged `mov rbx, [src2]; xor rax, rbx` |
| `and` | 2 | Direct `and rax, [src2]` vs. De Morgan `not rax; not rbx; or rax, rbx; not rax` |
| `mul` | 2 | `imul rax, [src2]` vs. register-staged `mov rbx, [src2]; imul rax, rbx` |
| `move` | 2 | `mov rax, [src]; mov [dst], rax` vs. `push qword [src]; pop qword [dst]` |
| `load_imm` | 2 | Direct `mov rax, [rsi]; add rsi, 8` vs. `lodsq` (`0x48, 0xAD`) |
| `cmp` | 2 | Direct `cmp rax, [rbp+rdi*8-0x80]` vs. register-staged `mov rbx, [rbp+rdi*8-0x80]; cmp rax, rbx` |

### Lifter & Condition Code Coverage (`L1` – `L6`)

- **Data movement & stack frame**: `mov`, `movsxd`, `movzx`, `cdqe`, `lea`, `push`, `pop`, `[rbp±disp]` local/argument slots
- **Arithmetic, bitwise, unary & shift**: `add`, `sub`, `imul`, `div`/`idiv` (8/16/32/64-bit, including `[base+disp]` with no index; 8-bit remainder stays in `ah`; 8/16-bit `shl`/`shr`/`sar` and 16-bit `imul` keep bits outside the operand), `cdq`, `cqo`, `inc`, `dec`, `and`, `or` (synthesized via MBA-compatible `(a ^ b) + (a & b)`), `xor`, `not`, `neg`, `shl`
- **Comparisons & tests**: `cmp` (64-bit and 32-bit `cmp32` across registers, immediates, and `[rbp±disp]`), `test reg, reg`, `test reg, imm`
- **Control flow & `jmp_if` condition codes (`1..=12`)**:
  - `1` = `JE`/`JZ`, `2` = `JNE`/`JNZ`
  - `3` = `JG` (signed `>`), `4` = `JL` (signed `<`), `5` = `JLE` (signed `<=`), `6` = `JGE` (signed `>=`)
  - `7` = `JA` (unsigned `>`), `8` = `JAE` (unsigned `>=`), `9` = `JB` (unsigned `<`), `10` = `JBE` (unsigned `<=`)
  - `11` = `JS` (`SF=1`), `12` = `JNS` (`SF=0`)

## Sample Programs

Eight MinGW-style C samples in `sample/`:

| Sample | Behavior |
|--------|----------|
| `hello` | `printf("Hello, World!\n")` — legacy `native_call` 1 or IAT `printf` when resolved |
| `puts_hello` | `puts("IAT puts hello")` — exercises the IAT Win64 `native_call` path |
| `loop` | Countdown loop |
| `arith` | Multi-operand arithmetic |
| `call` | Internal function calls |
| `nested` | Nested loops + `putchar` |
| `fact` | Recursive factorial |
| `str` | `LoadByte` string walk |

## Testing

```bash
cargo test
```

The test suite (**326 tests** where the two Linux mmap harnesses are built: 320 library unit tests + 6 integration tests; the binary harness reruns those units plus the CLI RVA parser). `cargo test` on Windows ran 318 library tests, 319 binary tests, and 6 integration tests. The suite runs on Linux without requiring a Windows runtime (including native Linux x64 mmap execution harnesses for `vm_stub`) and covers PE/IAT parsing, CFG collection, L1–L13 lifting (`movzx`, `movsx`, `movsxd`, `cdqe`, `cdq`, `cqo`, `shr`, `sar`, `div`/`idiv` including `[base+disp]`, partial `[rbp+disp]` moves, scaled `lea`, `jmp reg`, switch tables, scalar SSE, `comiss`/`ucomiss`, `--strict`), 32-register spill/scratch isolation, metadata scrubbing & multi-function `.knvmap` sidecar roundtrips, reference-VM native sleds, MBA & automatic constant unfolding / opaque predicates, handler polymorphism (`add`, `sub`, `xor`, `and`, `mul`, `move`, `load_imm`, `cmp`), transition-keyed maps, layout padding, stack ISA, nested VM execution, `BytecodeCipher`, fetch-time rolling wire decryption, multi-RVA trampolines, L9 per-slot register encoding, `madd` fusion, the L10 qword immediate cipher, the L11 register-index mask, the L12 call-stack return cipher, and the L13 data-stack cipher.

## Project Structure

```text
src/
├── vm/
│   ├── opcode.rs      - Logical VM opcodes
│   ├── opcode_map.rs  - L4a wire shuffle, KNV4 metadata, handler variant counts
│   ├── virt_isa.rs    - L5a virtual ISA split/merge & ALU polymorphism helpers
│   ├── dispatch.rs    - L4c table vs. threaded dispatch modes
│   ├── block_map.rs   - L4e/L5d per-transition opcode maps (KNV6)
│   ├── layout.rs      - L5c post-wire dead-byte padding plan (KNV7)
│   ├── isa_mode.rs    - L5e reg vs. stack virtual ISA mode
│   ├── nested_vm.rs   - L5f outer-decode + inner-execute plan
│   ├── l8.rs          - L8 rolling wire key and native-call micro-op names
│   ├── l9.rs          - L9 register-slot keys and madd fusion
│   ├── l10.rs         - L10 position-keyed qword immediate cipher
│   ├── l11.rs         - L11 position-keyed register-index mask
│   ├── l12.rs         - L12 per-depth call-stack return cipher
│   ├── l13.rs         - L13 per-depth data-stack cipher
│   └── machine.rs     - Reference Rust VM interpreter
├── ir/                - Layout/transition/ISA-aware bytecode disassembler & printer
├── pe/
│   ├── parser.rs      - PE32+ parser
│   ├── imports.rs     - PE import directory / IAT resolution
│   ├── cfg.rs         - CFG reconstruction & function collection
│   ├── lifter.rs      - iced-x86 lifter → VM bytecode
│   ├── mba.rs         - L4f/L5b/L6 MBA rewrites, OR synthesis, constant unfolding
│   ├── partial.rs     - L4d partial BB virtualization & native sleds (KNV5)
│   ├── threaded.rs    - L4c threaded dispatch pass
│   ├── layout_pass.rs - L5c bytecode layout padding & offset relocation
│   ├── vm_stub.rs     - Standalone x64 machine-code interpreter stub generator
│   └── packer.rs      - End-to-end `.knvest` section builder
├── pack/              - High-level pack orchestration
├── cli/               - CLI argument parsing
└── main.rs

sample/                - hello, puts_hello, loop, arith, call, nested, fact, str
tests/                 - Integration tests
```

## License

MIT License (see `LICENSE` file).

## Disclaimer

Educational tool for learning about code virtualization and PE file formats. Use only on your own binaries. Not intended for malicious use.
