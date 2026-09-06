# L4e: Per-block opcode-map rotation

## Design

L4e rotates the L4a opcode wire map at **basic-block entry** so the same semantic VM opcode (e.g. `load_imm`) encodes as **different raw bytes** in different blocks. This breaks static byte-frequency analysis across a function while keeping handler bodies and IR semantics unchanged.

### Block key → map rotation

At pack time, for each main-function BB id `b`:

```
block_seed = pack_seed ^ BLKE_SALT ^ b
block_map  = OpcodeMap::from_seed(block_seed)   // same Fisher–Yates shuffle as L4a (KNV4)
decode_key = high32(splitmix64(block_seed ^ BLKE_SALT))
```

The **pack seed** drives all diversification; the in-process stub never runs the shuffle PRNG.

### Block entry in bytecode

At the first lifted instruction of each virtualized BB, the lifter emits a fixed meta prefix:

```
[0xFD][bb_id u16 le]
```

`0xFD` is reserved (`META_WIRE_BYTE`) and never assigned to semantic opcodes. The VM handler `h_set_block_map` reads `bb_id`, looks up the matching entry in embedded **KNV6** metadata, copies the precomputed 256-slot handler redirect table into the writable dispatch table, and updates the runtime exit-wire byte used by the dispatch loop.

### Embedded metadata (KNV6)

After KNV4 (map seed + base wire table + dispatch mode) and KNV5 (L4d partial plan):

| Field | Size |
|-------|------|
| magic `KNV6` | 4 |
| version | 1 |
| global decode_key | u32 |
| entry count | u16 |
| per entry: bb_id | u16 |
| per entry: block decode_key | u32 |
| per entry: exit_wire | u8 + pad |
| per entry: wire[20] | 20 |
| per entry: handler_table | 1024 |

The stub **reads** these tables only; the packer precomputes handler_table images from finalized stub handler offsets.

### IR (`knvest ir`)

`knvest ir` prints:

1. L4c dispatch + L4a seed (unchanged)
2. L4d partial header when `--partial` (unchanged)
3. **L4e block opcode maps** table: BB id, per-block `decode_key`, `exit_wire`, sample `load_imm` wire
4. Disassembly with block-aware decode (shows `set_block_map` at BB entries)

### Compatibility

- **L4a** KNV4 base map remains the function-wide seed anchor.
- **L4b** Add handler polymorphism unchanged.
- **L4c** `--dispatch table|threaded` unchanged (threaded embed uses semantic handler offsets).
- **L4d** `--partial`, `run_native`, `bail_native` unchanged.
