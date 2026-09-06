# L4c: Threaded dispatch design note

## Summary

KnVest L4c adds a pack-time selectable VM dispatch mode alongside the existing handler-table loop.

| Mode | CLI | Default | Mechanism |
|------|-----|---------|-----------|
| **table** | `--dispatch table` (or omit) | yes | Central `dispatch` label reads opcode wire byte, indexes `handler_table[opcode]` (dword offsets), jumps to handler. Handlers tail-jump back to `dispatch`. |
| **threaded** | `--dispatch threaded` | no | Pack embeds a **per-instruction handler rel32** immediately after each opcode wire byte in the bytecode stream. Dispatch loads `movsxd rax, [rsi+1]`, adds `handler_table` base, advances `rsi` by 5, and jumps—**no opcode-indexed table lookup**. |

## How threaded differs from table

**Table dispatch** (subroutine threading):

1. `movzx eax, [rsi]` / `inc rsi`
2. `cmp al, exit_wire` → `h_exit`
3. `lea rbx, [handler_table]`
4. `movsxd rax, [rbx+rax*4]` — **indexed by current opcode byte**
5. `add rax, rbx` / `jmp rax`

**Threaded dispatch** (direct threading style with inline targets):

1. `movzx eax, [rsi]` (opcode still present for IR / handler operand layout)
2. `cmp al, exit_wire` → skip `opcode+rel32` then `h_exit`
3. `movsxd rax, [rsi+1]` — **next-handler offset from bytecode stream**
4. `lea rbx, [handler_table]` / `add rax, rbx` / `add rsi, 5` / `jmp rax`

Handlers are unchanged; only the dispatch prologue and bytecode layout differ. Logical IR is identical when disassembled with the correct mode (rel32 slots are skipped).

**Pack-time relocation:** `embed_thread_targets` inserts a 4-byte handler `rel32` after each opcode wire byte and **relocates** operands that encode bytecode positions:

- `jmp` / `call` / `jmp_if` targets (instruction-start offsets)
- `load_imm` / `load_str` embedded string offsets (16-byte-aligned positions at or past the code section)

Without this fixup, threaded `hello` and other control-flow samples jump into rel32 slots and fault or exit early.

**String pool:** trailing padding + embedded literals (hello `Hello, World!`, str `knvest`, IAT puts) live after the last VM instruction. `embed_thread_targets` must append `bytecode[code_end..]` after threading the insn stream; dropping that tail breaks stdio/IAT samples with empty stdout.

## Metadata

- KNV4 header **version 2** adds a dispatch wire byte after the version field.
- KNV4 v1 images default to `table`.
- `knvest ir` prints `L4c dispatch=<mode>`; L4d partial headers also include `dispatch=`.

## Diversification

- Opcode shuffle (L4a), Add polymorphism (L4b), and partial plans (L4d) remain seed-driven at pack time.
- The stub reads KNV4 dispatch mode and tables/keys only; it does not choose the mode.
- Thread rel32 values are derived from finalized handler offsets for the packed seed/map.
