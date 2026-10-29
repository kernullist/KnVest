use super::block_map::{BlockMapPlan, META_WIRE_BYTE};
use super::isa_mode::IsaMode;
use super::layout::BytecodeLayout;
use super::opcode::OpCode;
use super::opcode_map::OpcodeMap;
use std::collections::HashMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum VMError {
    #[error("Invalid opcode: {0:#x}")]
    InvalidOpcode(u8),
    #[error("Invalid register index: {0}")]
    InvalidRegister(u8),
    #[error("Stack underflow")]
    StackUnderflow,
    #[error("Stack overflow")]
    StackOverflow,
    #[error("Memory access violation at {0:#x}")]
    MemoryViolation(usize),
    #[error("Program counter out of bounds")]
    PCOutOfBounds,
    #[error("Division by zero")]
    DivisionByZero,
    #[error("Native call error: {0}")]
    NativeCallError(String),
}

pub type VMResult<T> = Result<T, VMError>;

enum MemLoc {
    Data(usize),
    Mem(usize),
}

pub const NUM_REGISTERS: usize = 32;
const STACK_SIZE: usize = 4096;
const MEMORY_SIZE: usize = 65536;

pub struct VirtualMachine {
    registers: [u64; NUM_REGISTERS],
    pc: usize,
    sp: usize,
    flags: u64,
    stack: Vec<u64>,
    memory: Vec<u8>,
    bytecode: Vec<u8>,
    opcode_map: Option<OpcodeMap>,
    block_map_plan: Option<BlockMapPlan>,
    layout: BytecodeLayout,
    /// Active L4e basic-block id (updated on META set_block_map).
    current_bb_id: u16,
    native_functions: HashMap<u64, fn(&mut VirtualMachine) -> VMResult<()>>,
    pub exit_code: Option<i32>,
    pub data_section: Vec<u8>,
    isa_mode: IsaMode,
    /// VM data-stack depth for stack-ISA ALU (mirrors stub [rbp-0xE8]).
    data_stack_depth: usize,
    data_stack: Vec<u64>,
    /// L8 XMM/SSE scalar file (low 64 bits; high 64 of a 128-bit slot is implicit zero).
    xmm_registers: [u64; crate::vm::l8::XMM_SLOT_COUNT],
    /// When set, the opcode wire byte is XOR-decrypted with `rolling_wire_mask(seed, pc)`.
    rolling_cipher: bool,
    rolling_seed: u64,
    /// L9: virtual register slots hold `plaintext XOR reg_slot_key(seed, slot)`.
    reg_encrypt: bool,
    reg_encrypt_seed: u64,
    /// L10: XOR qword immediates with `imm_cipher_mask(seed, offset)` on read.
    imm_cipher: bool,
    imm_seed: u64,
    /// RVAs observed by L8 direct calls (`0x4_0000_0000 | rva`).
    pub direct_calls: Vec<u32>,
    /// MXCSR. Reset value masks invalid/denormal/div0/overflow/underflow/precision.
    mxcsr: u32,
    /// Native sled image referenced by `RunNative` / `BailNative` offsets.
    native_sleds: Vec<u8>,
    /// `(rbp disp, VM spill reg)` pairs copied around a native sled, matching the stub.
    native_sync: Vec<(i32, u8)>,
}

impl VirtualMachine {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self {
            registers: [0; NUM_REGISTERS],
            pc: 0,
            sp: 0,
            flags: 0,
            stack: Vec::with_capacity(STACK_SIZE),
            memory: vec![0; MEMORY_SIZE],
            bytecode,
            opcode_map: None,
            block_map_plan: None,
            layout: BytecodeLayout::identity(),
            current_bb_id: 0,
            native_functions: HashMap::new(),
            exit_code: None,
            data_section: Vec::new(),
            isa_mode: IsaMode::Reg,
            data_stack_depth: 0,
            data_stack: Vec::with_capacity(STACK_SIZE),
            xmm_registers: [0; crate::vm::l8::XMM_SLOT_COUNT],
            rolling_cipher: false,
            rolling_seed: 0,
            reg_encrypt: false,
            reg_encrypt_seed: 0,
            imm_cipher: false,
            imm_seed: 0,
            direct_calls: Vec::new(),
            mxcsr: 0x1F80,
            native_sleds: Vec::new(),
            native_sync: Vec::new(),
        }
    }

    /// Attach the packed native-sled image so `RunNative` / `BailNative` apply it.
    pub fn with_native_sleds(mut self, sleds: Vec<u8>, sync: Vec<(i32, u8)>) -> Self {
        self.native_sleds = sleds;
        self.native_sync = sync;
        self
    }

    pub fn mxcsr(&self) -> u32 {
        self.mxcsr
    }

    pub fn set_mxcsr(&mut self, mxcsr: u32) {
        self.mxcsr = mxcsr;
    }

    /// Fetch-time idempotent rolling decryption. The bytecode image stays ciphertext.
    pub fn with_rolling_cipher(mut self, seed: u64) -> Self {
        self.rolling_cipher = true;
        self.rolling_seed = seed;
        self
    }

    /// Store every virtual register as `plaintext XOR reg_slot_key(seed, slot)`.
    /// Logical zeros are the keys themselves. Call this before writing registers.
    pub fn with_reg_encrypt(mut self, seed: u64) -> Self {
        self.reg_encrypt = true;
        self.reg_encrypt_seed = seed;
        for slot in 0..NUM_REGISTERS {
            self.registers[slot] = crate::vm::l9::reg_slot_key(seed, slot as u8);
        }
        self
    }

    /// Decrypt qword immediates while reading. The bytecode image stays ciphertext.
    pub fn with_imm_cipher(mut self, seed: u64) -> Self {
        self.imm_cipher = true;
        self.imm_seed = seed;
        self
    }

    pub fn get_xmm(&self, index: u8) -> VMResult<u64> {
        if (index as usize) < self.xmm_registers.len() {
            Ok(self.xmm_registers[index as usize])
        } else {
            Err(VMError::InvalidRegister(index))
        }
    }

    pub fn set_xmm(&mut self, index: u8, value: u64) -> VMResult<()> {
        if (index as usize) < self.xmm_registers.len() {
            self.xmm_registers[index as usize] = value;
            Ok(())
        } else {
            Err(VMError::InvalidRegister(index))
        }
    }

    pub fn with_isa_mode(mut self, isa_mode: IsaMode) -> Self {
        self.isa_mode = isa_mode;
        self
    }

    pub fn with_opcode_map(bytecode: Vec<u8>, opcode_map: OpcodeMap) -> Self {
        let mut vm = Self::new(bytecode);
        vm.opcode_map = Some(opcode_map);
        vm
    }

    pub fn with_block_maps(
        bytecode: Vec<u8>,
        opcode_map: OpcodeMap,
        block_map_plan: BlockMapPlan,
    ) -> Self {
        Self::with_block_maps_and_layout(
            bytecode,
            opcode_map,
            block_map_plan,
            BytecodeLayout::identity(),
        )
    }

    pub fn with_block_maps_and_layout(
        bytecode: Vec<u8>,
        opcode_map: OpcodeMap,
        block_map_plan: BlockMapPlan,
        layout: BytecodeLayout,
    ) -> Self {
        let mut vm = Self::with_opcode_map(bytecode, opcode_map);
        vm.block_map_plan = Some(block_map_plan);
        vm.layout = layout;
        vm
    }

    /// Construct a `VirtualMachine` by decrypting a `BytecodeCipher`-encrypted bytecode image.
    pub fn with_cipher_decrypted(
        ciphertext: &[u8],
        cipher: &super::layout::BytecodeCipher,
        opcode_map: OpcodeMap,
    ) -> Self {
        let plaintext = cipher.decrypt(ciphertext);
        Self::with_opcode_map(plaintext, opcode_map)
    }

    /// Read a logical VM register (`0..32`) through its seed-permuted physical slot in `cipher`.
    pub fn get_logical_register(
        &self,
        logical_reg: u8,
        cipher: &super::layout::BytecodeCipher,
    ) -> VMResult<u64> {
        self.get_register(cipher.map_reg(logical_reg))
    }

    /// Write a logical VM register (`0..32`) through its seed-permuted physical slot in `cipher`.
    pub fn set_logical_register(
        &mut self,
        logical_reg: u8,
        value: u64,
        cipher: &super::layout::BytecodeCipher,
    ) -> VMResult<()> {
        self.set_register(cipher.map_reg(logical_reg), value)
    }

    pub fn set_opcode_map(&mut self, opcode_map: OpcodeMap) {
        self.opcode_map = Some(opcode_map);
    }

    pub fn register_native(&mut self, id: u64, func: fn(&mut VirtualMachine) -> VMResult<()>) {
        self.native_functions.insert(id, func);
    }

    pub fn get_register(&self, reg: u8) -> VMResult<u64> {
        if (reg as usize) < NUM_REGISTERS {
            let raw = self.registers[reg as usize];
            Ok(if self.reg_encrypt {
                raw ^ crate::vm::l9::reg_slot_key(self.reg_encrypt_seed, reg)
            } else {
                raw
            })
        } else {
            Err(VMError::InvalidRegister(reg))
        }
    }

    fn plaintext_registers(&self) -> [u64; NUM_REGISTERS] {
        let mut regs = self.registers;
        if self.reg_encrypt {
            for (slot, value) in regs.iter_mut().enumerate() {
                *value ^= crate::vm::l9::reg_slot_key(self.reg_encrypt_seed, slot as u8);
            }
        }
        regs
    }

    fn store_plaintext_registers(&mut self, mut regs: [u64; NUM_REGISTERS]) {
        if self.reg_encrypt {
            for (slot, value) in regs.iter_mut().enumerate() {
                *value ^= crate::vm::l9::reg_slot_key(self.reg_encrypt_seed, slot as u8);
            }
        }
        self.registers = regs;
    }

    /// Slot image before register-file decoding. Equals [`get_register`] when L9 is off.
    pub fn raw_register(&self, reg: u8) -> VMResult<u64> {
        if (reg as usize) < NUM_REGISTERS {
            Ok(self.registers[reg as usize])
        } else {
            Err(VMError::InvalidRegister(reg))
        }
    }

    pub fn set_register(&mut self, reg: u8, value: u64) -> VMResult<()> {
        if (reg as usize) < NUM_REGISTERS {
            self.registers[reg as usize] = if self.reg_encrypt {
                value ^ crate::vm::l9::reg_slot_key(self.reg_encrypt_seed, reg)
            } else {
                value
            };
            Ok(())
        } else {
            Err(VMError::InvalidRegister(reg))
        }
    }

    pub fn write_memory_u64(&mut self, addr: usize, value: u64) -> VMResult<()> {
        let off = if addr >= 0x10000 {
            addr - 0x10000
        } else {
            addr
        };
        if off + 8 <= self.memory.len() {
            self.memory[off..off + 8].copy_from_slice(&value.to_le_bytes());
            Ok(())
        } else {
            Err(VMError::MemoryViolation(addr))
        }
    }

    pub fn read_memory_u64(&self, addr: usize) -> VMResult<u64> {
        let off = if addr >= 0x10000 {
            addr - 0x10000
        } else {
            addr
        };
        if off + 8 <= self.memory.len() {
            Ok(u64::from_le_bytes(
                self.memory[off..off + 8].try_into().unwrap(),
            ))
        } else {
            Err(VMError::MemoryViolation(addr))
        }
    }

    fn read_u8(&mut self) -> VMResult<u8> {
        if self.pc >= self.bytecode.len() {
            return Err(VMError::PCOutOfBounds);
        }
        let value = self.bytecode[self.pc];
        self.pc += 1;
        Ok(value)
    }

    fn read_u64(&mut self) -> VMResult<u64> {
        if self.pc + 8 > self.bytecode.len() {
            return Err(VMError::PCOutOfBounds);
        }
        let mut bytes = [0u8; 8];
        let offset = self.pc;
        bytes.copy_from_slice(&self.bytecode[self.pc..self.pc + 8]);
        self.pc += 8;
        let mut value = u64::from_le_bytes(bytes);
        if self.imm_cipher {
            value ^= crate::vm::l10::imm_cipher_mask(self.imm_seed, offset);
        }
        Ok(value)
    }

    fn push_stack(&mut self, value: u64) -> VMResult<()> {
        if self.stack.len() >= STACK_SIZE {
            return Err(VMError::StackOverflow);
        }
        self.stack.push(value);
        self.sp += 1;
        Ok(())
    }

    fn pop_stack(&mut self) -> VMResult<u64> {
        if self.sp == 0 {
            return Err(VMError::StackUnderflow);
        }
        self.sp -= 1;
        self.stack.pop().ok_or(VMError::StackUnderflow)
    }

    fn push_data_stack(&mut self, value: u64) -> VMResult<()> {
        if self.data_stack_depth >= STACK_SIZE {
            return Err(VMError::StackOverflow);
        }
        if self.data_stack_depth == self.data_stack.len() {
            self.data_stack.push(value);
        } else {
            self.data_stack[self.data_stack_depth] = value;
        }
        self.data_stack_depth += 1;
        Ok(())
    }

    fn pop_data_stack(&mut self) -> VMResult<u64> {
        if self.data_stack_depth == 0 {
            return Err(VMError::StackUnderflow);
        }
        self.data_stack_depth -= 1;
        Ok(self.data_stack[self.data_stack_depth])
    }

    fn skip_layout_pad_meta(&mut self) -> VMResult<()> {
        for _ in 0..self.layout.meta_post_wire_pad {
            self.read_u8()?;
        }
        Ok(())
    }

    fn skip_layout_pad_semantic(&mut self, op: OpCode) -> VMResult<()> {
        for _ in 0..self.layout.post_wire_pad_for(op) {
            self.read_u8()?;
        }
        Ok(())
    }

    fn read_u16(&mut self) -> VMResult<u16> {
        if self.pc + 2 > self.bytecode.len() {
            return Err(VMError::PCOutOfBounds);
        }
        let value = u16::from_le_bytes([self.bytecode[self.pc], self.bytecode[self.pc + 1]]);
        self.pc += 2;
        Ok(value)
    }

    pub fn run(&mut self) -> VMResult<()> {
        while self.exit_code.is_none() && self.pc < self.bytecode.len() {
            self.step()?;
        }
        Ok(())
    }

    #[cfg(test)]
    pub fn program_counter(&self) -> usize {
        self.pc
    }

    pub fn step(&mut self) -> VMResult<()> {
        let wire_off = self.pc;
        let mut opcode_byte = self.read_u8()?;
        if self.rolling_cipher {
            opcode_byte ^= crate::vm::l8::rolling_wire_mask(self.rolling_seed, wire_off);
        }

        if opcode_byte == META_WIRE_BYTE {
            let base_seed = self
                .opcode_map
                .as_ref()
                .ok_or(VMError::InvalidOpcode(opcode_byte))?
                .seed();
            self.skip_layout_pad_meta()?;
            let tx_id = self.read_u16()?;
            let new_map = if let Some(plan) = &self.block_map_plan {
                plan.map_for_tx(tx_id)
                    .map(|e| OpcodeMap::from_parts(base_seed, e.wire))
                    .ok_or(VMError::InvalidOpcode(META_WIRE_BYTE))?
            } else {
                BlockMapPlan::block_opcode_map(base_seed, tx_id as usize)
            };
            self.opcode_map = Some(new_map);
            self.current_bb_id = tx_id;
            return Ok(());
        }

        let opcode = if let Some(map) = &self.opcode_map {
            map.decode(opcode_byte)
                .ok_or(VMError::InvalidOpcode(opcode_byte))?
        } else {
            OpCode::from_u8(opcode_byte).ok_or(VMError::InvalidOpcode(opcode_byte))?
        };

        self.skip_layout_pad_semantic(opcode)?;

        match opcode {
            OpCode::Nop => {}
            OpCode::SetBlockMap => {
                // Handled via META_WIRE_BYTE before decode; unreachable in normal bytecode.
            }

            OpCode::LoadImm => {
                let reg = self.read_u8()?;
                let value = self.read_u64()?;
                self.set_register(reg, value)?;
            }

            OpCode::LoadMem => {
                let dst = self.read_u8()?;
                let addr_reg = self.read_u8()?;
                let addr = self.get_register(addr_reg)? as usize;
                if addr + 8 > MEMORY_SIZE {
                    return Err(VMError::MemoryViolation(addr));
                }
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&self.memory[addr..addr + 8]);
                self.set_register(dst, u64::from_le_bytes(bytes))?;
            }

            OpCode::StoreMem => {
                let addr_reg = self.read_u8()?;
                let src = self.read_u8()?;
                let addr = self.get_register(addr_reg)? as usize;
                let value = self.get_register(src)?;
                if addr + 8 > MEMORY_SIZE {
                    return Err(VMError::MemoryViolation(addr));
                }
                self.memory[addr..addr + 8].copy_from_slice(&value.to_le_bytes());
            }

            OpCode::Move => {
                let dst = self.read_u8()?;
                let src = self.read_u8()?;
                let value = self.get_register(src)?;
                self.set_register(dst, value)?;
            }

            OpCode::Add => {
                if self.isa_mode.is_stack() {
                    let dst = self.read_u8()?;
                    let val2 = self.pop_data_stack()?;
                    let val1 = self.pop_data_stack()?;
                    self.set_register(dst, val1.wrapping_add(val2))?;
                } else {
                    let dst = self.read_u8()?;
                    let src1 = self.read_u8()?;
                    let src2 = self.read_u8()?;
                    let val1 = self.get_register(src1)?;
                    let val2 = self.get_register(src2)?;
                    self.set_register(dst, val1.wrapping_add(val2))?;
                }
            }

            OpCode::Sub => {
                if self.isa_mode.is_stack() {
                    let dst = self.read_u8()?;
                    let val2 = self.pop_data_stack()?;
                    let val1 = self.pop_data_stack()?;
                    self.set_register(dst, val1.wrapping_sub(val2))?;
                } else {
                    let dst = self.read_u8()?;
                    let src1 = self.read_u8()?;
                    let src2 = self.read_u8()?;
                    let val1 = self.get_register(src1)?;
                    let val2 = self.get_register(src2)?;
                    self.set_register(dst, val1.wrapping_sub(val2))?;
                }
            }

            OpCode::Mul => {
                if self.isa_mode.is_stack() {
                    let dst = self.read_u8()?;
                    let val2 = self.pop_data_stack()?;
                    let val1 = self.pop_data_stack()?;
                    self.set_register(dst, val1.wrapping_mul(val2))?;
                } else {
                    let dst = self.read_u8()?;
                    let src1 = self.read_u8()?;
                    let src2 = self.read_u8()?;
                    let val1 = self.get_register(src1)?;
                    let val2 = self.get_register(src2)?;
                    self.set_register(dst, val1.wrapping_mul(val2))?;
                }
            }

            OpCode::And => {
                if self.isa_mode.is_stack() {
                    let dst = self.read_u8()?;
                    let val2 = self.pop_data_stack()?;
                    let val1 = self.pop_data_stack()?;
                    self.set_register(dst, val1 & val2)?;
                } else {
                    let dst = self.read_u8()?;
                    let src1 = self.read_u8()?;
                    let src2 = self.read_u8()?;
                    let val1 = self.get_register(src1)?;
                    let val2 = self.get_register(src2)?;
                    self.set_register(dst, val1 & val2)?;
                }
            }

            OpCode::Xor => {
                if self.isa_mode.is_stack() {
                    let dst = self.read_u8()?;
                    let val2 = self.pop_data_stack()?;
                    let val1 = self.pop_data_stack()?;
                    self.set_register(dst, val1 ^ val2)?;
                } else {
                    let dst = self.read_u8()?;
                    let src1 = self.read_u8()?;
                    let src2 = self.read_u8()?;
                    let val1 = self.get_register(src1)?;
                    let val2 = self.get_register(src2)?;
                    self.set_register(dst, val1 ^ val2)?;
                }
            }

            OpCode::Cmp => {
                let (val1, val2) = if self.isa_mode.is_stack() {
                    (self.pop_data_stack()?, self.pop_data_stack()?)
                } else {
                    let src1 = self.read_u8()?;
                    let src2 = self.read_u8()?;
                    (self.get_register(src1)?, self.get_register(src2)?)
                };
                let result = val1.wrapping_sub(val2);
                let zf = val1 == val2;
                let sf = (result as i64) < 0;
                let cf = val1 < val2;
                let of = ((val1 ^ val2) & (val1 ^ result)) >> 63 != 0;
                self.flags = (if zf { 0x40 } else { 0 })
                    | (if sf { 0x80 } else { 0 })
                    | (if cf { 0x01 } else { 0 })
                    | (if of { 0x800 } else { 0 });
            }

            OpCode::Cmp32 => {
                let (val1, val2) = if self.isa_mode.is_stack() {
                    (self.pop_data_stack()? as u32, self.pop_data_stack()? as u32)
                } else {
                    let src1 = self.read_u8()?;
                    let src2 = self.read_u8()?;
                    (
                        self.get_register(src1)? as u32,
                        self.get_register(src2)? as u32,
                    )
                };
                // Match native `cmp r32, r32`: ZF/SF/CF/OF come from the 32-bit result.
                let result = val1.wrapping_sub(val2);
                let zf = val1 == val2;
                let sf = (result as i32) < 0;
                let cf = val1 < val2;
                let of = ((val1 ^ val2) & (val1 ^ result)) >> 31 != 0;
                self.flags = (if zf { 0x40 } else { 0 })
                    | (if sf { 0x80 } else { 0 })
                    | (if cf { 0x01 } else { 0 })
                    | (if of { 0x800 } else { 0 });
            }

            OpCode::Jmp => {
                let offset = self.read_u64()? as usize;
                self.pc = offset;
            }

            OpCode::JmpIf => {
                let condition = self.read_u8()?;
                let offset = self.read_u64()? as usize;
                let cf = self.flags & 0x01 != 0;
                let zf = self.flags & 0x40 != 0;
                let sf = self.flags & 0x80 != 0;
                let of = self.flags & 0x800 != 0;
                let should_jump = match condition {
                    1 => zf,              // JE: ZF=1
                    2 => !zf,             // JNE: ZF=0
                    3 => !zf && sf == of, // JG: ZF=0 && SF==OF
                    4 => sf != of,        // JL: SF!=OF
                    5 => zf || sf != of,  // JLE: ZF=1 || SF!=OF
                    6 => sf == of,        // JGE: SF==OF
                    7 => !cf && !zf,      // JA: CF=0 && ZF=0
                    8 => !cf,             // JAE: CF=0
                    9 => cf,              // JB: CF=1
                    10 => cf || zf,       // JBE: CF=1 || ZF=1
                    11 => sf,             // JS: SF=1
                    12 => !sf,            // JNS: SF=0
                    _ => return Err(VMError::InvalidOpcode(condition)),
                };
                if should_jump {
                    self.pc = offset;
                }
            }

            OpCode::Call => {
                let offset = self.read_u64()? as usize;
                if self.block_map_plan.is_some() {
                    let ret_pc = self.pc as u64;
                    let caller_bb = u64::from(self.current_bb_id);
                    self.push_stack(ret_pc | (caller_bb << 32))?;
                } else {
                    self.push_stack(self.pc as u64)?;
                }
                self.pc = offset;
            }

            OpCode::Ret => {
                if self.block_map_plan.is_some() {
                    let packed = self.pop_stack()?;
                    self.pc = (packed & 0xFFFF_FFFF) as usize;
                    let caller_bb = (packed >> 32) as u16;
                    if let Some(plan) = &self.block_map_plan {
                        let base = self.opcode_map.as_ref().ok_or(VMError::InvalidOpcode(0))?;
                        let restored = plan
                            .map_for_tx(caller_bb)
                            .map(|e| OpcodeMap::from_parts(base.seed(), e.wire))
                            .ok_or(VMError::InvalidOpcode(0))?;
                        self.opcode_map = Some(restored);
                        self.current_bb_id = caller_bb;
                    }
                } else {
                    let return_addr = self.pop_stack()? as usize;
                    self.pc = return_addr;
                }
            }

            OpCode::NativeCall => {
                let func_id = self.read_u64()?;
                if let Some(reg) = crate::vm::l8::decode_jmp_reg(func_id) {
                    self.pc = self.get_register(reg)? as usize;
                } else if let Some((subop, dst, src)) = crate::vm::l8::decode_xmm(func_id) {
                    self.exec_xmm_micro(subop, dst, src)?;
                } else if let Some((kind, reg)) = crate::vm::l8::decode_div(func_id) {
                    self.exec_div_micro(kind, reg)?;
                } else if let Some((op, data, addr)) = crate::vm::l8::decode_mem(func_id) {
                    self.exec_mem_micro(op, data, addr)?;
                } else if let Some((dst, a, b, c)) = crate::vm::l9::decode_madd(func_id) {
                    let product = crate::vm::l9::exec_madd(
                        self.get_register(a)?,
                        self.get_register(b)?,
                        self.get_register(c)?,
                    );
                    self.set_register(dst, product)?;
                } else if let Some(rva) = crate::vm::l8::decode_direct_call(func_id) {
                    self.direct_calls.push(rva);
                    if let Some(func) = self.native_functions.get(&func_id).copied() {
                        func(self)?;
                    } else {
                        self.set_register(0, 0)?;
                    }
                } else if let Some(func) = self.native_functions.get(&func_id).copied() {
                    func(self)?;
                } else {
                    return Err(VMError::NativeCallError(format!(
                        "Unknown function ID: {}",
                        func_id
                    )));
                }
            }

            OpCode::Push => {
                let reg = self.read_u8()?;
                let value = self.get_register(reg)?;
                if self.isa_mode.is_stack() {
                    self.push_data_stack(value)?;
                } else {
                    self.push_stack(value)?;
                }
            }

            OpCode::Pop => {
                let reg = self.read_u8()?;
                let value = if self.isa_mode.is_stack() {
                    self.pop_data_stack()?
                } else {
                    self.pop_stack()?
                };
                self.set_register(reg, value)?;
            }

            OpCode::LoadByte => {
                let dst = self.read_u8()?;
                let addr_reg = self.read_u8()?;
                let addr = self.get_register(addr_reg)? as usize;
                let byte_val = self.read_mem(addr, 1)?;
                self.set_register(dst, byte_val)?;
            }

            OpCode::LoadStr => {
                let dst = self.read_u8()?;
                let offset = self.read_u64()? as usize;
                self.set_register(dst, offset as u64)?;
            }

            OpCode::Exit => {
                let code_reg = self.read_u8()?;
                let code = self.get_register(code_reg)? as i32;
                self.exit_code = Some(code);
            }

            OpCode::RunNative | OpCode::BailNative => {
                let sled_offset = self.read_u64()? as usize;
                let _orig_rva = self.read_u64()?;
                if !self.native_sleds.is_empty() {
                    self.exec_native_sled(sled_offset)?;
                }
            }
        }

        Ok(())
    }

    fn exec_div_micro(&mut self, kind: u8, divisor_reg: u8) -> VMResult<()> {
        let divisor = self.get_register(divisor_reg)?;
        let lo = self.get_register(0)?;
        let hi = self.get_register(2)?;
        match crate::vm::l8::exec_div_effect(kind, lo, hi, divisor) {
            Ok(crate::vm::l8::DivWrite::Both(quot, rem)) => {
                self.set_register(0, quot)?;
                self.set_register(2, rem)?;
                Ok(())
            }
            Ok(crate::vm::l8::DivWrite::Rax(rax)) => self.set_register(0, rax),
            Err(()) => Err(VMError::DivisionByZero),
        }
    }

    /// Address windows shared by `LoadByte` and pointer micros:
    /// `data_section`, then the `0x10000` alias of `memory`, then `memory` itself.
    fn locate_mem(&self, addr: usize, len: usize) -> VMResult<MemLoc> {
        let end = addr
            .checked_add(len)
            .ok_or(VMError::MemoryViolation(addr))?;
        if !self.data_section.is_empty() && addr < self.data_section.len() {
            if end <= self.data_section.len() {
                return Ok(MemLoc::Data(addr));
            }
            return Err(VMError::MemoryViolation(addr));
        }
        if addr >= 0x10000 && end <= 0x10000 + self.memory.len() {
            return Ok(MemLoc::Mem(addr - 0x10000));
        }
        if end <= self.memory.len() {
            return Ok(MemLoc::Mem(addr));
        }
        Err(VMError::MemoryViolation(addr))
    }

    fn read_mem(&self, addr: usize, len: usize) -> VMResult<u64> {
        let mut bytes = [0u8; 8];
        match self.locate_mem(addr, len)? {
            MemLoc::Data(off) => bytes[..len].copy_from_slice(&self.data_section[off..off + len]),
            MemLoc::Mem(off) => bytes[..len].copy_from_slice(&self.memory[off..off + len]),
        }
        Ok(u64::from_le_bytes(bytes))
    }

    fn write_mem(&mut self, addr: usize, value: u64, len: usize) -> VMResult<()> {
        let bytes = value.to_le_bytes();
        match self.locate_mem(addr, len)? {
            MemLoc::Data(off) => {
                self.data_section[off..off + len].copy_from_slice(&bytes[..len]);
            }
            MemLoc::Mem(off) => {
                self.memory[off..off + len].copy_from_slice(&bytes[..len]);
            }
        }
        Ok(())
    }

    fn exec_mem_micro(&mut self, op: u8, data_reg: u8, addr_reg: u8) -> VMResult<()> {
        let addr = self.get_register(addr_reg)? as usize;
        match op {
            crate::vm::l8::MEM_LOAD64 => {
                let value = self.read_mem(addr, 8)?;
                self.set_register(data_reg, value)
            }
            crate::vm::l8::MEM_LOAD32 => {
                let value = self.read_mem(addr, 4)?;
                self.set_register(data_reg, value)
            }
            crate::vm::l8::MEM_STORE64 => {
                let value = self.get_register(data_reg)?;
                self.write_mem(addr, value, 8)
            }
            crate::vm::l8::MEM_STORE32 => {
                let value = self.get_register(data_reg)?;
                self.write_mem(addr, value, 4)
            }
            crate::vm::l8::MEM_LOAD8 => {
                let byte = self.read_mem(addr, 1)?;
                let old = self.get_register(data_reg)?;
                self.set_register(data_reg, (old & !0xFF) | (byte & 0xFF))
            }
            crate::vm::l8::MEM_STORE8 => {
                let value = self.get_register(data_reg)?;
                self.write_mem(addr, value, 1)
            }
            crate::vm::l8::MEM_LOAD16 => {
                let word = self.read_mem(addr, 2)?;
                let old = self.get_register(data_reg)?;
                self.set_register(data_reg, (old & !0xFFFF) | (word & 0xFFFF))
            }
            crate::vm::l8::MEM_STORE16 => {
                let value = self.get_register(data_reg)?;
                self.write_mem(addr, value, 2)
            }
            crate::vm::l8::MEM_LOAD8_HI => {
                let byte = self.read_mem(addr, 1)?;
                let old = self.get_register(data_reg)?;
                self.set_register(data_reg, (old & !0xFF00) | ((byte & 0xFF) << 8))
            }
            crate::vm::l8::MEM_STORE8_HI => {
                let value = self.get_register(data_reg)? >> 8;
                self.write_mem(addr, value, 1)
            }
            _ => Err(VMError::NativeCallError(format!("unknown mem op {op}"))),
        }
    }

    fn exec_xmm_micro(&mut self, subop: u8, dst: u8, src: u8) -> VMResult<()> {
        let dest_bits = self.xmm_registers.get(dst as usize).copied().unwrap_or(0);
        let src_bits = self.xmm_registers.get(src as usize).copied().unwrap_or(0);
        let mut regs = self.plaintext_registers();
        let mut xmm = self.xmm_registers;
        match crate::vm::l8::exec_xmm(subop, dst, src, &mut xmm, &mut regs) {
            Ok(flags) => {
                self.store_plaintext_registers(regs);
                self.xmm_registers = xmm;
                if let Some(flags) = flags {
                    self.flags = flags;
                }
                if crate::vm::l8::compare_sets_invalid(subop, dest_bits, src_bits) {
                    self.mxcsr |= 1;
                    if self.mxcsr & 0x80 == 0 {
                        return Err(VMError::NativeCallError(
                            "xmm invalid-operation exception".to_string(),
                        ));
                    }
                }
                Ok(())
            }
            Err(()) => Err(VMError::NativeCallError(format!(
                "bad xmm micro-op subop={subop} dst={dst} src={src}"
            ))),
        }
    }

    /// Apply one native sled to VM registers and rbp spill slots.
    /// Loop-counter sleds are `[rbp+disp]` updates. Recognized GPR ops update VM
    /// registers. An unrecognized instruction is an error instead of a silent skip.
    fn exec_native_sled(&mut self, sled_offset: usize) -> VMResult<()> {
        if sled_offset >= self.native_sleds.len() {
            return Err(VMError::NativeCallError(format!(
                "native sled offset {sled_offset:#x} is past the sled image"
            )));
        }
        let bytes = &self.native_sleds[sled_offset..];
        let instrs = crate::pe::lifter::disassemble_x64_simple(bytes, 64);
        let sync = self.native_sync.clone();
        let mut frame: HashMap<i32, u8> = HashMap::new();
        for &(disp, reg) in &sync {
            let value = self.get_register(reg)? as u32;
            frame_write(&mut frame, disp, value as u64, 4);
        }
        for insn in &instrs {
            if matches!(insn.kind, crate::pe::lifter::X64InstrKind::Ret) {
                break;
            }
            self.apply_sled_insn(insn, &mut frame)?;
        }
        for &(disp, reg) in &sync {
            self.set_register(reg, frame_read(&frame, disp, 4))?;
        }
        Ok(())
    }

    fn apply_sled_insn(
        &mut self,
        insn: &crate::pe::lifter::X64Instruction,
        frame: &mut HashMap<i32, u8>,
    ) -> VMResult<()> {
        use crate::pe::lifter::{gpr_mem_width, X64InstrKind, X64Reg};
        let mem_width = |bytes: &[u8]| {
            let (width, _) = gpr_mem_width(bytes);
            width.max(1) as usize
        };
        match &insn.kind {
            X64InstrKind::Nop => Ok(()),
            X64InstrKind::MovRegImm { reg, imm } => self.set_register(reg.to_vm_reg(), *imm),
            X64InstrKind::MovRegMem { dst, base, offset }
                if matches!(base, X64Reg::Rbp | X64Reg::Ebp) =>
            {
                let width = mem_width(&insn.bytes);
                let loaded = frame_read(frame, *offset, width);
                let reg = dst.to_vm_reg();
                let old = self.get_register(reg)?;
                let (w, high) = gpr_mem_width(&insn.bytes);
                let value = match (w, high) {
                    (8, true) => (old & !0xFF00) | ((loaded & 0xFF) << 8),
                    (8, _) => (old & !0xFF) | (loaded & 0xFF),
                    (16, _) => (old & !0xFFFF) | (loaded & 0xFFFF),
                    (32, _) => loaded & 0xFFFF_FFFF,
                    _ => loaded,
                };
                self.set_register(reg, value)
            }
            X64InstrKind::MovMemReg { base, offset, src }
                if matches!(base, X64Reg::Rbp | X64Reg::Ebp) =>
            {
                let width = mem_width(&insn.bytes);
                let value = self.get_register(src.to_vm_reg())?;
                frame_write(frame, *offset, value, width);
                Ok(())
            }
            X64InstrKind::MovMemImm { base, offset, imm }
                if matches!(base, X64Reg::Rbp | X64Reg::Ebp) =>
            {
                let width = mem_width(&insn.bytes).min(4);
                frame_write(frame, *offset, *imm as u64, width);
                Ok(())
            }
            X64InstrKind::AddMemImm { base, offset, imm }
                if matches!(base, X64Reg::Rbp | X64Reg::Ebp) =>
            {
                let cur = frame_read(frame, *offset, 4) as u32;
                let next = cur.wrapping_add(*imm);
                frame_write(frame, *offset, next as u64, 4);
                self.flags = flags_from_add32(cur, *imm);
                Ok(())
            }
            X64InstrKind::SubMemImm { base, offset, imm }
                if matches!(base, X64Reg::Rbp | X64Reg::Ebp) =>
            {
                let cur = frame_read(frame, *offset, 4) as u32;
                let next = cur.wrapping_sub(*imm);
                frame_write(frame, *offset, next as u64, 4);
                self.flags = flags_from_sub32(cur, *imm);
                Ok(())
            }
            X64InstrKind::CmpMemImm { base, offset, imm }
                if matches!(base, X64Reg::Rbp | X64Reg::Ebp) =>
            {
                let cur = frame_read(frame, *offset, 4) as u32;
                self.flags = flags_from_sub32(cur, *imm);
                Ok(())
            }
            other => Err(VMError::NativeCallError(format!(
                "native sled instruction is not executable in the reference VM: {other:?}"
            ))),
        }
    }
}

fn frame_write(frame: &mut HashMap<i32, u8>, disp: i32, value: u64, len: usize) {
    let bytes = value.to_le_bytes();
    for i in 0..len {
        frame.insert(disp + i as i32, bytes[i]);
    }
}

fn frame_read(frame: &HashMap<i32, u8>, disp: i32, len: usize) -> u64 {
    let mut bytes = [0u8; 8];
    for i in 0..len.min(8) {
        bytes[i] = frame.get(&(disp + i as i32)).copied().unwrap_or(0);
    }
    u64::from_le_bytes(bytes)
}

fn flags_from_sub32(a: u32, b: u32) -> u64 {
    let result = a.wrapping_sub(b);
    let zf = a == b;
    let sf = (result as i32) < 0;
    let cf = a < b;
    let of = ((a ^ b) & (a ^ result)) >> 31 != 0;
    (if zf { 0x40 } else { 0 })
        | (if sf { 0x80 } else { 0 })
        | (if cf { 0x01 } else { 0 })
        | (if of { 0x800 } else { 0 })
}

fn flags_from_add32(a: u32, b: u32) -> u64 {
    let result = a.wrapping_add(b);
    let zf = result == 0;
    let sf = (result as i32) < 0;
    let cf = result < a;
    let of = ((a ^ result) & (b ^ result)) >> 31 != 0;
    (if zf { 0x40 } else { 0 })
        | (if sf { 0x80 } else { 0 })
        | (if cf { 0x01 } else { 0 })
        | (if of { 0x800 } else { 0 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_imm() {
        let mut bytecode = vec![
            OpCode::LoadImm as u8,
            0, // Load into register 0
        ];
        bytecode.extend_from_slice(&42u64.to_le_bytes());
        bytecode.push(OpCode::Exit as u8);
        bytecode.push(0);

        let mut vm = VirtualMachine::new(bytecode);
        vm.run().unwrap();
        assert_eq!(vm.get_register(0).unwrap(), 42);
    }

    #[test]
    fn test_add() {
        let mut bytecode = vec![OpCode::LoadImm as u8, 0];
        bytecode.extend_from_slice(&10u64.to_le_bytes());
        bytecode.push(OpCode::LoadImm as u8);
        bytecode.push(1);
        bytecode.extend_from_slice(&20u64.to_le_bytes());
        bytecode.extend_from_slice(&[OpCode::Add as u8, 2, 0, 1]);
        bytecode.push(OpCode::Exit as u8);
        bytecode.push(2);

        let mut vm = VirtualMachine::new(bytecode);
        vm.run().unwrap();
        assert_eq!(vm.get_register(2).unwrap(), 30);
    }

    #[test]
    fn test_l4e_call_ret_restores_block_opcode_map() {
        use crate::vm::block_map::{emit_block_map_refresh, BlockMapPlan, META_WIRE_BYTE};
        use crate::vm::OpcodeMap;

        let seed = 0x4C34_4100u64;
        let base = OpcodeMap::from_seed(seed);
        let mut plan = BlockMapPlan {
            decode_key: BlockMapPlan::global_decode_key(seed),
            entries: vec![],
            ..Default::default()
        };
        plan.record_block(seed, 0);
        plan.record_block(seed, 1);

        let mut bytecode = Vec::new();
        emit_block_map_refresh(&mut bytecode, 0);
        bytecode.push(plan.map_for_bb_or_base(0, &base).encode(OpCode::LoadImm));
        bytecode.push(0);
        bytecode.extend_from_slice(&1u64.to_le_bytes());
        let call_pos = bytecode.len();
        bytecode.push(plan.map_for_bb_or_base(0, &base).encode(OpCode::Call));
        bytecode.extend_from_slice(&0u64.to_le_bytes());
        emit_block_map_refresh(&mut bytecode, 0);
        bytecode.push(plan.map_for_bb_or_base(0, &base).encode(OpCode::LoadImm));
        bytecode.push(1);
        bytecode.extend_from_slice(&3u64.to_le_bytes());
        bytecode.push(plan.map_for_bb_or_base(0, &base).encode(OpCode::Exit));
        bytecode.push(0);
        let callee_off = bytecode.len();
        bytecode[call_pos + 1..call_pos + 9].copy_from_slice(&(callee_off as u64).to_le_bytes());
        emit_block_map_refresh(&mut bytecode, 1);
        bytecode.push(plan.map_for_bb_or_base(1, &base).encode(OpCode::LoadImm));
        bytecode.push(0);
        bytecode.extend_from_slice(&2u64.to_le_bytes());
        bytecode.push(plan.map_for_bb_or_base(1, &base).encode(OpCode::Ret));

        let mut vm = VirtualMachine::with_block_maps(bytecode, base, plan);
        vm.run().unwrap();
        assert_eq!(vm.get_register(0).unwrap(), 2);
        assert_eq!(vm.get_register(1).unwrap(), 3);
    }

    #[test]
    fn test_set_block_map_meta_wire_rotates_opcode_map() {
        use crate::vm::block_map::{emit_block_map_refresh, BlockMapPlan, META_WIRE_BYTE};
        use crate::vm::OpcodeMap;

        let seed = 0x4C34_4100u64;
        let base = OpcodeMap::from_seed(seed);
        let mut plan = BlockMapPlan {
            decode_key: BlockMapPlan::global_decode_key(seed),
            entries: vec![],
            ..Default::default()
        };
        plan.record_block(seed, 0);
        plan.record_block(seed, 1);

        let mut bytecode = Vec::new();
        emit_block_map_refresh(&mut bytecode, 0);
        assert_eq!(bytecode[0], META_WIRE_BYTE);
        bytecode.push(plan.map_for_bb_or_base(0, &base).encode(OpCode::LoadImm));
        bytecode.push(0);
        bytecode.extend_from_slice(&7u64.to_le_bytes());
        bytecode.push(plan.map_for_bb_or_base(0, &base).encode(OpCode::Exit));
        bytecode.push(0);

        let mut vm = VirtualMachine::with_block_maps(bytecode, base, plan);
        vm.run().unwrap();
        assert_eq!(vm.get_register(0).unwrap(), 7);
    }

    #[test]
    fn test_stack_operations() {
        let mut bytecode = vec![OpCode::LoadImm as u8, 0];
        bytecode.extend_from_slice(&100u64.to_le_bytes());
        bytecode.extend_from_slice(&[OpCode::Push as u8, 0]);
        bytecode.extend_from_slice(&[OpCode::Pop as u8, 1]);
        bytecode.push(OpCode::Exit as u8);
        bytecode.push(1);

        let mut vm = VirtualMachine::new(bytecode);
        vm.run().unwrap();
        assert_eq!(vm.get_register(1).unwrap(), 100);
    }

    #[test]
    fn test_jmpif_unsigned_and_sign_conditions() {
        let eval_cond = |lhs: u64, rhs: u64, cond: u8| -> u64 {
            let mut bc = Vec::new();
            bc.push(OpCode::LoadImm as u8);
            bc.push(1);
            bc.extend_from_slice(&lhs.to_le_bytes());
            bc.push(OpCode::LoadImm as u8);
            bc.push(2);
            bc.extend_from_slice(&rhs.to_le_bytes());
            bc.extend_from_slice(&[OpCode::Cmp as u8, 1, 2]);
            bc.push(OpCode::JmpIf as u8);
            bc.push(cond);
            let jmp_patch = bc.len();
            bc.extend_from_slice(&0u64.to_le_bytes());
            // Not taken: r0 = 0
            bc.push(OpCode::LoadImm as u8);
            bc.push(0);
            bc.extend_from_slice(&0u64.to_le_bytes());
            bc.extend_from_slice(&[OpCode::Exit as u8, 0]);
            let taken_pc = bc.len() as u64;
            bc[jmp_patch..jmp_patch + 8].copy_from_slice(&taken_pc.to_le_bytes());
            // Taken: r0 = 1
            bc.push(OpCode::LoadImm as u8);
            bc.push(0);
            bc.extend_from_slice(&1u64.to_le_bytes());
            bc.extend_from_slice(&[OpCode::Exit as u8, 0]);

            let mut vm = VirtualMachine::new(bc);
            vm.run().unwrap();
            vm.get_register(0).unwrap()
        };

        // JA (7): unsigned >
        assert_eq!(eval_cond(10, 5, 7), 1);
        assert_eq!(eval_cond(5, 5, 7), 0);
        assert_eq!(eval_cond(u64::MAX, 1, 7), 1);
        // JAE (8): unsigned >=
        assert_eq!(eval_cond(5, 5, 8), 1);
        assert_eq!(eval_cond(4, 5, 8), 0);
        // JB (9): unsigned <
        assert_eq!(eval_cond(4, 5, 9), 1);
        assert_eq!(eval_cond(5, 5, 9), 0);
        assert_eq!(eval_cond(1, u64::MAX, 9), 1);
        // JBE (10): unsigned <=
        assert_eq!(eval_cond(5, 5, 10), 1);
        assert_eq!(eval_cond(6, 5, 10), 0);
        // JS (11): SF == 1 (result negative)
        assert_eq!(eval_cond(3, 10, 11), 1);
        assert_eq!(eval_cond(10, 3, 11), 0);
        // JNS (12): SF == 0 (result non-negative)
        assert_eq!(eval_cond(10, 3, 12), 1);
        assert_eq!(eval_cond(3, 10, 12), 0);
    }

    #[test]
    fn cmp32_flags_use_32bit_signed_result() {
        let eval_cond = |lhs: u64, rhs: u64, cond: u8| -> u64 {
            let mut bc = Vec::new();
            bc.push(OpCode::LoadImm as u8);
            bc.push(1);
            bc.extend_from_slice(&lhs.to_le_bytes());
            bc.push(OpCode::LoadImm as u8);
            bc.push(2);
            bc.extend_from_slice(&rhs.to_le_bytes());
            bc.extend_from_slice(&[OpCode::Cmp32 as u8, 1, 2]);
            bc.push(OpCode::JmpIf as u8);
            bc.push(cond);
            let jmp_patch = bc.len();
            bc.extend_from_slice(&0u64.to_le_bytes());
            bc.push(OpCode::LoadImm as u8);
            bc.push(0);
            bc.extend_from_slice(&0u64.to_le_bytes());
            bc.extend_from_slice(&[OpCode::Exit as u8, 0]);
            let taken_pc = bc.len() as u64;
            bc[jmp_patch..jmp_patch + 8].copy_from_slice(&taken_pc.to_le_bytes());
            bc.push(OpCode::LoadImm as u8);
            bc.push(0);
            bc.extend_from_slice(&1u64.to_le_bytes());
            bc.extend_from_slice(&[OpCode::Exit as u8, 0]);

            let mut vm = VirtualMachine::new(bc);
            vm.run().unwrap();
            vm.get_register(0).unwrap()
        };

        // JL: 0xFFFFFFFF as i32 is -1, which is < 0
        assert_eq!(eval_cond(0xFFFF_FFFF, 0, 4), 1);
        assert_eq!(eval_cond(0, 0xFFFF_FFFF, 4), 0);
        // JG: 0 > -1
        assert_eq!(eval_cond(0, 0xFFFF_FFFF, 3), 1);
        // JS: 0x80000000 - 0 is negative as i32
        assert_eq!(eval_cond(0x8000_0000, 0, 11), 1);
        // JA (unsigned): 0xFFFFFFFF > 0
        assert_eq!(eval_cond(0xFFFF_FFFF, 0, 7), 1);
        // INT_MIN - 1: result is positive (SF=0) with OF=1, so JL (SF!=OF) is taken
        assert_eq!(eval_cond(0x8000_0000, 1, 4), 1);
    }

    #[test]
    fn jmpif_unknown_condition_is_an_error() {
        let mut bc = Vec::new();
        bc.push(OpCode::LoadImm as u8);
        bc.push(1);
        bc.extend_from_slice(&1u64.to_le_bytes());
        bc.push(OpCode::LoadImm as u8);
        bc.push(2);
        bc.extend_from_slice(&1u64.to_le_bytes());
        bc.extend_from_slice(&[OpCode::Cmp as u8, 1, 2]);
        bc.push(OpCode::JmpIf as u8);
        bc.push(0);
        bc.extend_from_slice(&0u64.to_le_bytes());
        bc.extend_from_slice(&[OpCode::Exit as u8, 0]);
        let mut vm = VirtualMachine::new(bc);
        assert!(matches!(vm.run(), Err(VMError::InvalidOpcode(0))));
    }

    #[test]
    fn set_block_map_unknown_tx_id_is_an_error() {
        use crate::vm::block_map::{emit_block_map_refresh, BlockMapPlan};

        let seed = 0x4C34_4100u64;
        let base = OpcodeMap::from_seed(seed);
        let mut plan = BlockMapPlan {
            decode_key: BlockMapPlan::global_decode_key(seed),
            entries: vec![],
            ..Default::default()
        };
        plan.record_block(seed, 0);

        let mut bytecode = Vec::new();
        emit_block_map_refresh(&mut bytecode, 99);
        bytecode.push(plan.map_for_bb_or_base(0, &base).encode(OpCode::Exit));
        bytecode.push(0);

        let mut vm = VirtualMachine::with_block_maps(bytecode, base, plan);
        assert!(matches!(vm.run(), Err(VMError::InvalidOpcode(_))));
    }

    #[test]
    fn load_byte_out_of_range_is_a_memory_violation() {
        let mut bc = vec![OpCode::LoadImm as u8, 1];
        bc.extend_from_slice(&0x2_0000u64.to_le_bytes());
        bc.extend_from_slice(&[OpCode::LoadByte as u8, 0, 1, OpCode::Exit as u8, 0]);
        let mut vm = VirtualMachine::new(bc);
        assert!(matches!(vm.run(), Err(VMError::MemoryViolation(_))));
    }

    #[test]
    fn byte_load_merges_data_section_into_ah() {
        use crate::vm::l8::{encode_mem, MEM_LOAD8_HI};
        let mut bc = vec![OpCode::LoadImm as u8, 0];
        bc.extend_from_slice(&0x1122_u64.to_le_bytes());
        bc.push(OpCode::LoadImm as u8);
        bc.push(1);
        bc.extend_from_slice(&0u64.to_le_bytes());
        bc.push(OpCode::NativeCall as u8);
        bc.extend_from_slice(&encode_mem(MEM_LOAD8_HI, 0, 1).to_le_bytes());
        bc.extend_from_slice(&[OpCode::Exit as u8, 0]);
        let mut vm = VirtualMachine::new(bc);
        vm.data_section = vec![0xAB];
        vm.run().unwrap();
        assert_eq!(vm.get_register(0).unwrap(), 0xAB22);
    }

    #[test]
    fn comiss_qnan_sets_mxcsr_ie_and_ucomiss_does_not() {
        use crate::vm::l8::{encode_xmm, XMM_COMISS, XMM_UCOMISS};
        let mut bc = vec![OpCode::NativeCall as u8];
        bc.extend_from_slice(&encode_xmm(XMM_COMISS, 0, 1).to_le_bytes());
        bc.extend_from_slice(&[OpCode::Exit as u8, 0]);
        let mut vm = VirtualMachine::new(bc.clone());
        vm.set_xmm(0, f32::NAN.to_bits() as u64).unwrap();
        vm.set_xmm(1, 1.0f32.to_bits() as u64).unwrap();
        vm.run().unwrap();
        assert_eq!(vm.mxcsr() & 1, 1, "comiss on QNaN sets IE");
        assert_eq!(
            vm.mxcsr() & 0x80,
            0x80,
            "default MXCSR keeps invalid masked"
        );

        let mut quiet = vec![OpCode::NativeCall as u8];
        quiet.extend_from_slice(&encode_xmm(XMM_UCOMISS, 0, 1).to_le_bytes());
        quiet.extend_from_slice(&[OpCode::Exit as u8, 0]);
        let mut vm = VirtualMachine::new(quiet);
        vm.set_xmm(0, f32::NAN.to_bits() as u64).unwrap();
        vm.set_xmm(1, 1.0f32.to_bits() as u64).unwrap();
        vm.run().unwrap();
        assert_eq!(vm.mxcsr() & 1, 0, "ucomiss on QNaN does not set IE");

        let mut vm = VirtualMachine::new(bc);
        vm.set_mxcsr(0);
        vm.set_xmm(0, f32::NAN.to_bits() as u64).unwrap();
        vm.set_xmm(1, 1.0f32.to_bits() as u64).unwrap();
        assert!(
            vm.run().is_err(),
            "unmasked comiss on QNaN is an invalid operation"
        );
    }

    #[test]
    fn run_native_applies_rbp_sled_to_spill_slot() {
        let mut bc = vec![OpCode::LoadImm as u8, 10];
        bc.extend_from_slice(&5u64.to_le_bytes());
        bc.push(OpCode::RunNative as u8);
        bc.extend_from_slice(&0u64.to_le_bytes());
        bc.extend_from_slice(&0u64.to_le_bytes());
        bc.extend_from_slice(&[OpCode::Exit as u8, 10]);
        // sub dword ptr [rbp-4], 1; ret
        let sled = vec![0x83, 0x6D, 0xFC, 0x01, 0xC3];
        let mut vm = VirtualMachine::new(bc).with_native_sleds(sled, vec![(-4, 10)]);
        vm.run().unwrap();
        assert_eq!(vm.get_register(10).unwrap(), 4);
    }
}
