# L5d: Transition-keyed opcode maps

## Design

L5d extends L4e per-block opcode maps with **path-dependent** maps keyed by
control-transfer edges. The same semantic basic block can encode identical VM
operations with **different raw wire bytes** depending on which predecessor
entered it (DynOpVm-style educational model; no proprietary code).

### Transition key → map rotation

For each CFG edge `(pred_bb → succ_bb)` at pack time:

```
transition_seed = pack_seed ^ TRNS_SALT ^ (succ_bb | (pred_bb << 32))
transition_map  = OpcodeMap::from_seed(transition_seed)
decode_key      = high32(splitmix64(transition_seed))
```

`pred_bb = 0xFFFF` (`ENTRY_PRED_BB`) denotes function / callee entry.

### Block entry in bytecode

The meta prefix is unchanged in size; the operand is now a dense **tx_id**
(index into KNV6), not a bare `bb_id`:

```
[0xFD][tx_id u16 le]
```

`h_set_block_map` searches KNV6 v2 entries by `tx_id`, copies the matching
redirect table, and tracks the active transition in `[rbp-0x120]` for
table-mode `ret` restore.

### Embedded metadata (KNV6 v2)

| Field | Size |
|-------|------|
| magic `KNV6` | 4 |
| version `2` | 1 |
| global decode_key | u32 |
| entry count | u16 |
| per entry: tx_id | u16 |
| per entry: bb_id | u16 |
| per entry: pred_bb_id | u16 |
| per entry: block decode_key | u32 |
| per entry: exit_wire | u8 + pad |
| per entry: wire[20] | 20 |
| per entry: handler_table | 1024 |

Multi-predecessor blocks use **edge landing pads** (`set_block_map` + a
transition-reencoded copy of the linear path from the succ body through the
back-edge jmp) so each incoming path executes with its own wire map. Fallthrough
entry keeps the original lifted bytecode; jmp edges target the pad.

### IR (`knvest ir`)

`knvest ir` prints:

1. L4c dispatch + L4a seed (unchanged)
2. L4d partial header when `--partial` (unchanged)
3. **L5d transition opcode maps** table: `tx_id`, `bb_id`, `pred_bb`,
   `decode_key`, `exit_wire`, sample `load_imm` wire, **map_hash**
4. Disassembly: `set_block_map tx, bb, pred` operands

### Compatibility

- L4a–f, L5a/b/c gates preserved (opcode map, Add poly, partial/bail/run_native,
  dispatch modes, MBA, layout pads).
- Diversification remains in pack seed / generator; stub only consumes KNV6.
