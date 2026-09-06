use crate::vm::dispatch::DispatchMode;
use crate::vm::block_map::{BlockMapPlan, HandlerRedirectPlan, KNV6_ENTRY_SIZE, KNV6_HEADER_SIZE, META_WIRE_BYTE};
use crate::vm::opcode_map::{CANONICAL_HANDLER_LABELS, CANONICAL_OPCODES, OpcodeMap, PackMetadata};
use std::collections::HashMap;

// L2 VM interpreter frame map (rbp-relative; disp32 = signed i32 little-endian)
//   VM r0..r15     [rbp-0x80]..[rbp-0x08]   reg n → [rbp + n*8 - 0x80]
//     r1 = 88 FF FF FF, r2 = 90 FF FF FF (NOT 78/70 — those are -0x88 / flags -0x90)
//   cmp flags      [rbp-0x90]  bytes 70 FF FF FF
//   bytecode rsi   [rbp-0x98]  bytes 68 FF FF FF  (native_call save / h_call scratch)
//   stdout handle  [rbp-0xA0]  bytes 60 FF FF FF
//   ExitProcess    [rbp-0xA8]  bytes 58 FF FF FF
//   WriteFile      [rbp-0xB0]  bytes 50 FF FF FF
//   GetStdHandle   [rbp-0xB8]  bytes 48 FF FF FF
//   GPA            [rbp-0xC0]  bytes 40 FF FF FF
//   call depth     [rbp-0xC8]  bytes 38 FF FF FF
//   bytes written  [rbp-0xD0]  bytes 30 FF FF FF  (WriteFile out; do not clobber)
//   current bb_id  [rbp-0x120] bytes E0 FE FF FF  (L4e table mode; restored on ret)
//   active redirect [rbp-0x130] bytes D0 FE FF FF (L4e table: ptr to KNV6 redirect dwords)
//   VM r12         [rbp-0x20]  bytes E0 FF FF FF  (do not alias with current_bb_id)
//   push depth     [rbp-0xE8]  bytes 18 FF FF FF
//   char buf       [rbp-0xF0]  bytes 10 FF FF FF  (nc2/nc3 digit buffer; do not clobber)
//   ret addrs      [rbp + depth*8 - 0x200]       (lo32=bytecode index, hi32=caller bb_id)
//   data stack     [rbp + idx*8 - 0x380]         (idx 16 must stay below ret[0] at -0x200)
//   nc_iat spill   [rbp-0x500..-0x510]          (VM r10..r12; below ret/data — no overlap)
//   VM frame save  [rbp-0x118]                  (run_native re-anchors VM base from here)
//   native side    native_frame_ptr in .knvest   (prologue cache; handler uses direct lea r14)
pub fn create_vm_interpreter_stub(
    _image_base: u64,
    _section_rva: u32,
    map: &OpcodeMap,
    dispatch_mode: DispatchMode,
    knv5: &[u8],
    block_map_plan: &BlockMapPlan,
    native_sleds: &[u8],
    native_sync: &[(i32, u8)],
) -> (Vec<u8>, usize, usize, HandlerRedirectPlan) {
    let mut e = StubEmitter::new(map, dispatch_mode, native_sync, block_map_plan);
    e.emit_prologue_and_api_resolve();
    e.emit_dispatch_loop();
    e.emit_handler_table_placeholder();
    e.emit_handlers();
    e.emit_strings_and_marker(knv5, block_map_plan, native_sleds);
    e.finalize()
}

struct StubEmitter {
    code: Vec<u8>,
    labels: HashMap<&'static str, usize>,
    rel32: Vec<(usize, &'static str)>,
    lea_rip: Vec<(usize, &'static str)>,
    handler_table_start: Option<usize>,
    exit_cmp_patch_pos: Option<usize>,
    opcode_map: OpcodeMap,
    dispatch_mode: DispatchMode,
    native_sync: Vec<(i32, u8)>,
    block_map_plan: BlockMapPlan,
    knv6_offset: Option<usize>,
}

impl StubEmitter {
    fn new(
        map: &OpcodeMap,
        dispatch_mode: DispatchMode,
        native_sync: &[(i32, u8)],
        block_map_plan: &BlockMapPlan,
    ) -> Self {
        Self {
            code: Vec::new(),
            labels: HashMap::new(),
            rel32: Vec::new(),
            lea_rip: Vec::new(),
            handler_table_start: None,
            exit_cmp_patch_pos: None,
            opcode_map: map.clone(),
            dispatch_mode,
            native_sync: native_sync.to_vec(),
            block_map_plan: block_map_plan.clone(),
            knv6_offset: None,
        }
    }

    fn pos(&self) -> usize {
        self.code.len()
    }

    fn emit(&mut self, bytes: &[u8]) {
        self.code.extend_from_slice(bytes);
    }

    fn label(&mut self, name: &'static str) {
        self.labels.insert(name, self.pos());
    }

    fn jmp_rel32(&mut self, target: &'static str) {
        self.emit(&[0xE9, 0, 0, 0, 0]);
        self.rel32.push((self.pos() - 4, target));
    }

    fn jcc_rel32(&mut self, cc: u8, target: &'static str) {
        self.emit(&[0x0F, cc, 0, 0, 0, 0]);
        self.rel32.push((self.pos() - 4, target));
    }

    fn jcc_rel32_short(&mut self, cc: u8, target: &'static str) {
        // Map rel8 jcc opcodes to their rel32 near equivalents (0F xx)
        let near = match cc {
            0x72 => 0x82, // jb/jc
            0x73 => 0x83, // jae/jnb
            0x74 => 0x84, // je/jz
            0x75 => 0x85, // jne/jnz
            0x76 => 0x86, // jbe/jna
            0x77 => 0x87, // ja/jnbe
            0x7C => 0x8C, // jl
            0x7D => 0x8D, // jge
            0x7E => 0x8E, // jle
            0x7F => 0x8F, // jg
            _ => cc,
        };
        self.jcc_rel32(near, target);
    }

    fn lea_rip_rel32(&mut self, rex: u8, modrm_reg: u8, target: &'static str) {
        self.emit_rip_rel32(rex, 0x8D, modrm_reg, target);
    }

    fn emit_mov_qword_from_rip_label(&mut self, dst_reg: u8, target: &'static str) {
        self.emit_rip_rel32(if dst_reg >= 8 { 0x4C } else { 0x48 }, 0x8B, dst_reg, target);
    }

    fn emit_mov_qword_to_rip_label(&mut self, src_reg: u8, target: &'static str) {
        self.emit_rip_rel32(if src_reg >= 8 { 0x4C } else { 0x48 }, 0x89, src_reg, target);
    }

    fn emit_rip_rel32(&mut self, rex: u8, opcode: u8, modrm_reg: u8, target: &'static str) {
        self.emit(&[rex, opcode, 0x05 | ((modrm_reg & 7) << 3), 0, 0, 0, 0]);
        self.lea_rip.push((self.pos() - 4, target));
    }

    /// `lea rbx, [rip+handler_table]` — threaded dispatch and legacy table tests.
    fn emit_lea_handler_table_rbx(&mut self) {
        self.emit(&[0x48, 0x8D, 0x1D, 0, 0, 0, 0]);
        self.lea_rip.push((self.pos() - 4, "handler_table"));
    }

    /// `lea r10, [rip+handler_table]` — table dispatch add base (redirect dwords live elsewhere).
    fn emit_lea_handler_table_r10(&mut self) {
        self.lea_rip_rel32(0x4C, 2, "handler_table");
    }

    fn emit_init_active_redirect_ptr_to_handler_table(&mut self) {
        // lea rax,[handler_table]; mov [rbp-0x130], rax — frame slot (Windows-safe vs rip store).
        self.lea_rip_rel32(0x48, 0, "handler_table");
        self.emit_mov_qword_to_rbp_from_reg(0, -0x130);
    }

    /// Emit `mov dst, src` (Intel syntax, 64-bit reg-reg via opcode 89 /r).
    fn emit_mov_reg_reg(&mut self, dst: u8, src: u8) {
        debug_assert!(dst < 16 && src < 16);
        let mut rex = 0x48u8; // REX.W
        if src >= 8 {
            rex |= 0x04; // REX.R — src in reg field
        }
        if dst >= 8 {
            rex |= 0x01; // REX.B — dst in r/m field
        }
        let modrm = 0xC0 | ((src & 7) << 3) | (dst & 7);
        self.emit(&[rex, 0x89, modrm]);
    }

    fn emit_init_native_frame_ptr(&mut self) {
        // lea rax, [rip+native_stack_top]; sub rax,0x100; and rax,-16; mov [rip+native_frame_ptr], rax
        self.lea_rip_rel32(0x48, 0, "native_stack_top");
        self.emit(&[0x48, 0x2D, 0x00, 0x01, 0x00, 0x00]); // sub rax, 0x100
        self.emit(&[0x48, 0x83, 0xE0, 0xF0]); // and rax, -16
        self.emit_mov_qword_to_rip_label(0, "native_frame_ptr");
    }

    fn emit_load_native_locals_base_into_r14(&mut self) {
        // Direct .knvest absolute: lea r14,[native_stack_top]; sub r14,0x100; and r14,-16
        self.lea_rip_rel32(0x4C, 6, "native_stack_top");
        self.emit(&[0x49, 0x81, 0xEE, 0x00, 0x01, 0x00, 0x00]); // sub r14, 0x100
        self.emit(&[0x49, 0x83, 0xE6, 0xF0]); // and r14, -16
    }

    fn jmp_to_dispatch(&mut self) {
        self.jmp_rel32("dispatch");
    }

    fn emit_prologue_and_api_resolve(&mut self) {
        self.emit(&[0x55]);
        self.emit(&[0x48, 0x89, 0xE5]);
        self.emit(&[0x48, 0x81, 0xEC, 0x20, 0x05, 0x00, 0x00]); // sub rsp, 0x520 (frame incl. nc_iat scratch)
        self.emit(&[0x48, 0x83, 0xE4, 0xF0]);
        // Zero L2 call depth [rbp-0xC8], push depth [rbp-0xE8], and L4e current bb_id [rbp-0x120]
        self.emit(&[0x48, 0xC7, 0x85, 0x38, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00]);
        self.emit(&[0x48, 0xC7, 0x85, 0x18, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00]);
        self.emit_mov_word_imm_to_rbp(-0x120, 0); // mov word [rbp-0x120], 0
        self.emit(&[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00]);
        self.emit(&[0x48, 0x8B, 0x40, 0x18]);
        self.emit(&[0x4C, 0x8D, 0x58, 0x10]);
        self.lea_rip_rel32(0x4C, 2, "k32_str");

        self.emit(&[0x49, 0x8B, 0x0B]);
        self.label("module_loop");
        self.emit(&[0x49, 0x39, 0xCB]);
        self.jcc_rel32(0x84, "module_fail");

        self.emit(&[0x48, 0x8B, 0x71, 0x60]);
        self.emit(&[0x4D, 0x89, 0xD0]);
        self.label("name_cmp_loop");
        self.emit(&[0x41, 0x0F, 0xB7, 0x00]);
        self.emit(&[0x0F, 0xB7, 0x16]);
        self.emit(&[0x83, 0xF8, 0x41]);
        self.jcc_rel32_short(0x72, "lowercase1_done");
        self.emit(&[0x83, 0xF8, 0x5A]);
        self.jcc_rel32_short(0x77, "lowercase1_done");
        self.emit(&[0x83, 0xC8, 0x20]);
        self.label("lowercase1_done");
        self.emit(&[0x83, 0xFA, 0x41]);
        self.jcc_rel32_short(0x72, "lowercase2_done");
        self.emit(&[0x83, 0xFA, 0x5A]);
        self.jcc_rel32_short(0x77, "lowercase2_done");
        self.emit(&[0x83, 0xCA, 0x20]);
        self.label("lowercase2_done");
        self.emit(&[0x39, 0xD0]);
        self.jcc_rel32_short(0x75, "module_next");
        self.emit(&[0x85, 0xD2]);
        self.jcc_rel32_short(0x74, "name_cmp_done");
        self.emit(&[0x49, 0x83, 0xC0, 0x02]);
        self.emit(&[0x48, 0x83, 0xC6, 0x02]);
        self.jmp_rel32("name_cmp_loop");

        self.label("module_next");
        self.emit(&[0x48, 0x8B, 0x09]); // mov rcx, [rcx] — advance InMemoryOrderModuleList
        self.jmp_rel32("module_loop");

        self.label("name_cmp_done");
        self.emit(&[0x48, 0x8B, 0x59, 0x30]);
        self.emit(&[0x8B, 0x43, 0x3C]);
        self.emit(&[0x8B, 0x84, 0x18, 0x88, 0x00, 0x00, 0x00]);
        self.emit(&[0x48, 0x01, 0xD8]);
        self.emit(&[0x8B, 0x78, 0x20]);
        self.emit(&[0x48, 0x01, 0xDF]);
        self.emit(&[0x8B, 0x48, 0x24]);
        self.emit(&[0x48, 0x01, 0xD9]);
        self.emit(&[0x8B, 0x50, 0x1C]);
        self.emit(&[0x48, 0x01, 0xDA]);
        self.emit(&[0x8B, 0x70, 0x18]);

        self.label("search_loop");
        self.emit(&[0x85, 0xF6]);
        self.jcc_rel32_short(0x74, "module_fail");
        self.emit(&[0x48, 0xFF, 0xCE]);
        self.emit(&[0x8B, 0x04, 0xB7]);
        self.emit(&[0x48, 0x01, 0xD8]);
        self.emit(&[0x49, 0x89, 0xC1]);
        self.lea_rip_rel32(0x4C, 0, "gpa_str");

        self.label("strcmp_loop");
        self.emit(&[0x41, 0x8A, 0x00]);
        self.emit(&[0x41, 0x3A, 0x01]);
        self.jcc_rel32_short(0x75, "search_next");
        self.emit(&[0x84, 0xC0]);
        self.jcc_rel32_short(0x74, "strcmp_done");
        self.emit(&[0x49, 0xFF, 0xC0]);
        self.emit(&[0x49, 0xFF, 0xC1]);
        self.jmp_rel32("strcmp_loop");

        self.label("search_next");
        self.jmp_rel32("search_loop");

        self.label("strcmp_done");
        self.emit(&[0x0F, 0xB7, 0x04, 0x71]);
        self.emit(&[0x8B, 0x04, 0x82]);
        self.emit(&[0x48, 0x01, 0xD8]);
        self.emit(&[0x48, 0x89, 0x85, 0x40, 0xFF, 0xFF, 0xFF]);

        self.emit(&[0x48, 0x89, 0xD9]);
        self.lea_rip_rel32(0x48, 2, "gsth_str");
        self.emit(&[0x48, 0x83, 0xEC, 0x20]);
        self.emit(&[0xFF, 0x95, 0x40, 0xFF, 0xFF, 0xFF]);
        self.emit(&[0x48, 0x83, 0xC4, 0x20]);
        self.emit(&[0x48, 0x89, 0x85, 0x48, 0xFF, 0xFF, 0xFF]);

        self.emit(&[0x48, 0x89, 0xD9]);
        self.lea_rip_rel32(0x48, 2, "wf_str");
        self.emit(&[0x48, 0x83, 0xEC, 0x20]);
        self.emit(&[0xFF, 0x95, 0x40, 0xFF, 0xFF, 0xFF]);
        self.emit(&[0x48, 0x83, 0xC4, 0x20]);
        self.emit(&[0x48, 0x89, 0x85, 0x50, 0xFF, 0xFF, 0xFF]);

        self.emit(&[0x48, 0x89, 0xD9]);
        self.lea_rip_rel32(0x48, 2, "ep_str");
        self.emit(&[0x48, 0x83, 0xEC, 0x20]);
        self.emit(&[0xFF, 0x95, 0x40, 0xFF, 0xFF, 0xFF]);
        self.emit(&[0x48, 0x83, 0xC4, 0x20]);
        self.emit(&[0x48, 0x89, 0x85, 0x58, 0xFF, 0xFF, 0xFF]);

        self.emit(&[0x48, 0xC7, 0xC1, 0xF5, 0xFF, 0xFF, 0xFF]);
        self.emit(&[0x48, 0x83, 0xEC, 0x20]);
        self.emit(&[0xFF, 0x95, 0x48, 0xFF, 0xFF, 0xFF]);
        self.emit(&[0x48, 0x83, 0xC4, 0x20]);
        self.emit(&[0x48, 0x89, 0x85, 0x60, 0xFF, 0xFF, 0xFF]);

        self.emit_init_native_frame_ptr();
        if self.dispatch_mode == DispatchMode::Table {
            self.emit_init_active_redirect_ptr_to_handler_table();
        }
        self.lea_rip_rel32(0x48, 6, "bytecode");
        self.emit(&[0x48, 0x89, 0xF6]);
        self.jmp_rel32("dispatch");

        self.label("module_fail");
        self.emit(&[0xCC]);
    }

    fn emit_dispatch_loop(&mut self) {
        self.label("dispatch");
        match self.dispatch_mode {
            DispatchMode::Table => self.emit_table_dispatch_loop(),
            DispatchMode::Threaded => self.emit_threaded_dispatch_loop(),
        }
    }

    /// L4 default: opcode-indexed handler offset table + central dispatch.
    fn emit_table_dispatch_loop(&mut self) {
        self.emit(&[0x0F, 0xB6, 0x06]);
        self.emit(&[0x48, 0xFF, 0xC6]);
        self.emit(&[0x3A, 0x05, 0, 0, 0, 0]); // cmp al, byte [rip+exit_wire_cmp_slot]
        self.exit_cmp_patch_pos = Some(self.pos() - 4);
        self.lea_rip.push((self.pos() - 4, "exit_wire_cmp_slot"));
        self.jcc_rel32(0x84, "h_exit");
        // Redirect dwords come from active KNV6 entry (or BB0 handler_table at prologue).
        self.emit_lea_handler_table_r10();
        self.emit_mov_qword_from_rbp_to_reg(3, -0x130);
        self.emit(&[0x48, 0x63, 0x04, 0x83]); // movsxd rax, [rbx+rax*4]
        self.emit(&[0x4C, 0x01, 0xD0]); // add rax, r10
        self.emit(&[0xFF, 0xE0]);
    }

    /// L4c threaded: per-instruction handler rel32 in bytecode stream (no opcode-indexed lookup).
    fn emit_threaded_dispatch_loop(&mut self) {
        self.emit(&[0x0F, 0xB6, 0x06]); // movzx eax, byte [rsi]
        self.emit(&[0x3A, 0x05, 0, 0, 0, 0]); // cmp al, byte [rip+exit_wire_cmp_slot]
        self.exit_cmp_patch_pos = Some(self.pos() - 4);
        self.lea_rip.push((self.pos() - 4, "exit_wire_cmp_slot"));
        self.jcc_rel32(0x84, "h_exit_threaded");
        self.emit(&[0x48, 0x63, 0x46, 0x01]); // movsxd rax, dword [rsi+1]
        self.emit_lea_handler_table_rbx();
        self.emit(&[0x48, 0x01, 0xD8]); // add rax, rbx
        self.emit(&[0x48, 0x83, 0xC6, 0x05]); // add rsi, 5 (opcode + rel32)
        self.emit(&[0xFF, 0xE0]); // jmp rax
        self.label("h_exit_threaded");
        self.emit(&[0x48, 0x83, 0xC6, 0x05]); // skip opcode + rel32 before exit operand
        self.jmp_rel32("h_exit");
    }

    fn emit_handlers(&mut self) {
        self.emit_handler_set_block_map();
        let order = *self.opcode_map.handler_emit_order();
        for &idx in &order {
            match CANONICAL_OPCODES[idx as usize] {
                crate::vm::OpCode::Nop => self.emit_handler_nop(),
                crate::vm::OpCode::LoadImm => self.emit_handler_load_imm(),
                crate::vm::OpCode::Move => self.emit_handler_move(),
                crate::vm::OpCode::Add => self.emit_handler_add(),
                crate::vm::OpCode::Sub => self.emit_handler_sub(),
                crate::vm::OpCode::Mul => self.emit_handler_mul(),
                crate::vm::OpCode::Cmp => self.emit_handler_cmp(),
                crate::vm::OpCode::Jmp => self.emit_handler_jmp(),
                crate::vm::OpCode::JmpIf => self.emit_handler_jmpif(),
                crate::vm::OpCode::Call => self.emit_handler_call(),
                crate::vm::OpCode::Ret => self.emit_handler_ret(),
                crate::vm::OpCode::NativeCall => self.emit_handler_native_call(),
                crate::vm::OpCode::Push => self.emit_handler_push(),
                crate::vm::OpCode::Pop => self.emit_handler_pop(),
                crate::vm::OpCode::LoadByte => self.emit_handler_load_byte(),
                crate::vm::OpCode::Cmp32 => self.emit_handler_cmp32(),
                crate::vm::OpCode::And => self.emit_handler_and(),
                crate::vm::OpCode::RunNative => self.emit_handler_run_native(),
                crate::vm::OpCode::BailNative => self.emit_handler_bail_native(),
                crate::vm::OpCode::Exit => self.emit_handler_exit(),
                _ => unreachable!("canonical opcode set only"),
            }
        }
    }

    fn emit_handler_nop(&mut self) {
        self.label("h_nop");
        self.jmp_to_dispatch();
    }

    /// L4e: refresh opcode wire -> handler table from KNV6 entry for bb_id operand.
    fn emit_handler_set_block_map(&mut self) {
        self.label("h_set_block_map");
        // movzx r8d, word [rsi] — REX.R for r8 dest only (0x44); 0x45 wrongly sets REX.B → [r14]
        self.emit(&[0x44, 0x0F, 0xB7, 0x06]);
        // add rsi, 2
        self.emit(&[0x48, 0x83, 0xC6, 0x02]);
        self.emit_block_map_resolve_r15();
        self.label("h_set_block_map_found");
        // Reject bogus KNV6 images: handler_table must start with dword >= 1024.
        self.emit(&[0x41, 0x81, 0x7F, 0x1C, 0x00, 0x04, 0x00, 0x00]); // cmp dword [r15+0x1C], 1024
        self.jcc_rel32_short(0x72, "h_set_block_map_fail");
        self.emit_block_map_apply_and_dispatch();
        self.label("h_set_block_map_fail");
        self.jmp_rel32("module_fail");
    }

    /// r8 = bb_id operand; rsi = bytecode PC. Sets r15 → matching KNV6 entry header.
    fn emit_block_map_resolve_r15(&mut self) {
        self.label("h_set_block_map_resolve");
        // movzx ecx, word [rip + knv6_count]
        self.emit(&[0x0F, 0xB7, 0x0D, 0, 0, 0, 0]);
        self.lea_rip.push((self.pos() - 4, "knv6_count"));
        // lea r15, [rip + knv6_block_maps]; add r15, KNV6_HEADER_SIZE
        self.lea_rip_rel32(0x4D, 7, "knv6_block_maps");
        let header = KNV6_HEADER_SIZE as u32;
        self.emit(&[
            0x49,
            0x81,
            0xC7,
            (header & 0xFF) as u8,
            ((header >> 8) & 0xFF) as u8,
            ((header >> 16) & 0xFF) as u8,
            ((header >> 24) & 0xFF) as u8,
        ]);
        self.label("h_set_block_map_search");
        // cmp word [r15], r8w — match entry.bb_id (REX.R+REX.B for r8 vs [r15])
        self.emit(&[0x66, 0x4D, 0x39, 0x07]);
        self.jcc_rel32_short(0x74, "h_set_block_map_found");
        let stride = KNV6_ENTRY_SIZE as u32;
        self.emit(&[
            0x49,
            0x81,
            0xC7,
            (stride & 0xFF) as u8,
            ((stride >> 8) & 0xFF) as u8,
            ((stride >> 16) & 0xFF) as u8,
            ((stride >> 24) & 0xFF) as u8,
        ]); // add r15, KNV6_ENTRY_SIZE
        self.emit(&[0xFF, 0xC9]); // dec ecx
        self.jcc_rel32_short(0x75, "h_set_block_map_search");
        self.jmp_rel32("h_set_block_map_fail");
    }

    fn emit_block_map_apply_and_dispatch(&mut self) {
        // mov [rbp-0x120], r8w — track active bb for table-mode ret restore
        self.emit_mov_word_to_rbp_from_r8(-0x120);
        // mov al, [r15+6] exit_wire
        self.emit(&[0x41, 0x8A, 0x47, 0x06]);
        // mov [rip+exit_wire_cmp_slot], al
        self.emit(&[0x88, 0x05, 0, 0, 0, 0]);
        self.lea_rip.push((self.pos() - 4, "exit_wire_cmp_slot"));
        // Point dispatch at this KNV6 entry's embedded redirect table (frame slot, not rip).
        self.emit(&[0x49, 0x8D, 0x47, 0x1C]); // lea rax, [r15+0x1C]
        self.emit_mov_qword_to_rbp_from_reg(0, -0x130);
        self.jmp_to_dispatch();
    }

    fn emit_handler_load_imm(&mut self) {
        self.label("h_load_imm");
        self.emit(&[0x0F, 0xB6, 0x0E]);
        self.emit(&[0x48, 0xFF, 0xC6]);
        self.emit(&[0x48, 0x8B, 0x06]);
        self.emit(&[0x48, 0x83, 0xC6, 0x08]);
        self.emit(&[0x48, 0x89, 0x44, 0xCD, 0x80]);
        self.jmp_to_dispatch();
    }

    fn emit_handler_move(&mut self) {
        self.label("h_move");
        self.emit(&[0x0F, 0xB6, 0x0E]);
        self.emit(&[0x48, 0xFF, 0xC6]);
        self.emit(&[0x0F, 0xB6, 0x3E]);
        self.emit(&[0x48, 0xFF, 0xC6]);
        self.emit(&[0x48, 0x8B, 0x44, 0xFD, 0x80]);
        self.emit(&[0x48, 0x89, 0x44, 0xCD, 0x80]);
        self.jmp_to_dispatch();
    }

    fn emit_handler_add(&mut self) {
        self.label("h_add");
        match self.opcode_map.add_handler_variant() {
            0 => self.emit_handler_add_v0(),
            1 => self.emit_handler_add_v1(),
            _ => self.emit_handler_add_v2(),
        }
    }

    /// Add v0: `add rax, [src2]` after loading src1 into rax.
    fn emit_handler_add_v0(&mut self) {
        self.emit_add_operand_reads();
        self.emit(&[0x48, 0x8B, 0x44, 0xFD, 0x80]); // mov rax, [rbp+rdi*8-0x80]
        self.emit(&[0x48, 0x03, 0x44, 0xD5, 0x80]); // add rax, [rbp+rdx*8-0x80]
        self.emit_add_store_and_dispatch();
    }

    /// Add v1: `lea rax, [rax+rbx]` after loading both operands.
    fn emit_handler_add_v1(&mut self) {
        self.emit_add_operand_reads();
        self.emit(&[0x48, 0x8B, 0x44, 0xFD, 0x80]); // mov rax, [rbp+rdi*8-0x80]
        self.emit(&[0x48, 0x8B, 0x5C, 0xD5, 0x80]); // mov rbx, [rbp+rdx*8-0x80]
        self.emit(&[0x48, 0x8D, 0x04, 0x03]); // lea rax, [rbx+rax]
        self.emit_add_store_and_dispatch();
    }

    /// Add v2: store src1 to dst, reload dst, then add src2 (two-phase add).
    fn emit_handler_add_v2(&mut self) {
        self.emit_add_operand_reads();
        self.emit(&[0x48, 0x8B, 0x44, 0xFD, 0x80]); // mov rax, [rbp+rdi*8-0x80]
        self.emit(&[0x48, 0x89, 0x44, 0xCD, 0x80]); // mov [rbp+rcx*8-0x80], rax
        self.emit(&[0x48, 0x8B, 0x44, 0xCD, 0x80]); // mov rax, [rbp+rcx*8-0x80]
        self.emit(&[0x48, 0x03, 0x44, 0xD5, 0x80]); // add rax, [rbp+rdx*8-0x80]
        self.emit_add_store_and_dispatch();
    }

    fn emit_add_operand_reads(&mut self) {
        self.emit(&[0x0F, 0xB6, 0x0E]); // movzx ecx, byte [rsi]
        self.emit(&[0x48, 0xFF, 0xC6]); // inc rsi
        self.emit(&[0x0F, 0xB6, 0x3E]); // movzx edi, byte [rsi]
        self.emit(&[0x48, 0xFF, 0xC6]); // inc rsi
        self.emit(&[0x0F, 0xB6, 0x16]); // movzx edx, byte [rsi]
        self.emit(&[0x48, 0xFF, 0xC6]); // inc rsi
    }

    fn emit_add_store_and_dispatch(&mut self) {
        self.emit(&[0x48, 0x89, 0x44, 0xCD, 0x80]); // mov [rbp+rcx*8-0x80], rax
        self.jmp_to_dispatch();
    }

    fn emit_handler_sub(&mut self) {
        self.label("h_sub");
        self.emit(&[0x0F, 0xB6, 0x0E]);
        self.emit(&[0x48, 0xFF, 0xC6]);
        self.emit(&[0x0F, 0xB6, 0x3E]);
        self.emit(&[0x48, 0xFF, 0xC6]);
        self.emit(&[0x0F, 0xB6, 0x16]);
        self.emit(&[0x48, 0xFF, 0xC6]);
        self.emit(&[0x48, 0x8B, 0x44, 0xFD, 0x80]);
        self.emit(&[0x48, 0x2B, 0x44, 0xD5, 0x80]);
        self.emit(&[0x48, 0x89, 0x44, 0xCD, 0x80]);
        self.jmp_to_dispatch();
    }

    fn emit_handler_mul(&mut self) {
        self.label("h_mul");
        self.emit(&[0x0F, 0xB6, 0x0E]);
        self.emit(&[0x48, 0xFF, 0xC6]);
        self.emit(&[0x0F, 0xB6, 0x3E]);
        self.emit(&[0x48, 0xFF, 0xC6]);
        self.emit(&[0x0F, 0xB6, 0x16]);
        self.emit(&[0x48, 0xFF, 0xC6]);
        self.emit(&[0x48, 0x8B, 0x44, 0xFD, 0x80]);
        self.emit(&[0x48, 0x0F, 0xAF, 0x44, 0xD5, 0x80]);
        self.emit(&[0x48, 0x89, 0x44, 0xCD, 0x80]);
        self.jmp_to_dispatch();
    }

    fn emit_handler_and(&mut self) {
        self.label("h_and");
        self.emit(&[0x0F, 0xB6, 0x0E]);
        self.emit(&[0x48, 0xFF, 0xC6]);
        self.emit(&[0x0F, 0xB6, 0x3E]);
        self.emit(&[0x48, 0xFF, 0xC6]);
        self.emit(&[0x0F, 0xB6, 0x16]);
        self.emit(&[0x48, 0xFF, 0xC6]);
        self.emit(&[0x48, 0x8B, 0x44, 0xFD, 0x80]);
        self.emit(&[0x48, 0x23, 0x44, 0xD5, 0x80]);
        self.emit(&[0x48, 0x89, 0x44, 0xCD, 0x80]);
        self.jmp_to_dispatch();
    }

    fn emit_mov_from_r13_spill(&mut self, spill_reg: u8) {
        let disp = (spill_reg as i32) * 8 - 0x80;
        self.emit_mov_from_r13(0, disp);
    }

    fn emit_mov_to_r13_spill(&mut self, spill_reg: u8) {
        let disp = (spill_reg as i32) * 8 - 0x80;
        self.emit_mov_to_r13(0, disp);
    }

    fn emit_mov_from_r13(&mut self, reg: u8, disp: i32) {
        if (-128..=127).contains(&disp) {
            self.emit(&[0x49, 0x8B, (reg << 3) | 0x45, disp as u8]);
        } else {
            self.emit(&[0x49, 0x8B, (reg << 3) | 0x84, 0x25]);
            self.emit(&disp.to_le_bytes());
        }
    }

    fn emit_mov_to_r13(&mut self, reg: u8, disp: i32) {
        if (-128..=127).contains(&disp) {
            self.emit(&[0x49, 0x89, (reg << 3) | 0x45, disp as u8]);
        } else {
            self.emit(&[0x49, 0x89, (reg << 3) | 0x84, 0x25]);
            self.emit(&disp.to_le_bytes());
        }
    }

    fn emit_mov_from_r13_slot(&mut self, disp: i32) {
        if (-128..=127).contains(&disp) {
            self.emit(&[0x49, 0x8B, 0x4D, disp as u8]); // mov rcx, [r13+disp8]
        } else {
            self.emit(&[0x49, 0x8B, 0x8C, 0x25]); // mov rcx, [r13+disp32]
            self.emit(&disp.to_le_bytes());
        }
    }

    fn emit_mov_to_r13_slot(&mut self, disp: i32) {
        if (-128..=127).contains(&disp) {
            self.emit(&[0x49, 0x89, 0x4D, disp as u8]); // mov [r13+disp8], rcx
        } else {
            self.emit(&[0x49, 0x89, 0x8C, 0x25]); // mov [r13+disp32], rcx
            self.emit(&disp.to_le_bytes());
        }
    }

    fn emit_mov_to_rcx_disp(&mut self, disp: i32) {
        if (-128..=127).contains(&disp) {
            self.emit(&[0x48, 0x89, 0x41, disp as u8]);
        } else {
            self.emit(&[0x48, 0x89, 0x81]);
            self.emit(&disp.to_le_bytes());
        }
    }

    fn emit_mov_from_rcx_disp(&mut self, disp: i32) {
        if (-128..=127).contains(&disp) {
            self.emit(&[0x48, 0x8B, 0x41, disp as u8]);
        } else {
            self.emit(&[0x48, 0x8B, 0x81]);
            self.emit(&disp.to_le_bytes());
        }
    }

    fn emit_mov_dword_from_r13_spill(&mut self, spill_reg: u8) {
        let disp = (spill_reg as i32) * 8 - 0x80;
        if (-128..=127).contains(&disp) {
            self.emit(&[0x41, 0x8B, 0x45, disp as u8]); // mov eax, dword [r13+disp8]
        } else {
            self.emit(&[0x41, 0x8B, 0x84, 0x25]); // mov eax, dword [r13+disp32]
            self.emit(&disp.to_le_bytes());
        }
    }

    fn emit_mov_dword_to_r13_spill(&mut self, spill_reg: u8) {
        let disp = (spill_reg as i32) * 8 - 0x80;
        if (-128..=127).contains(&disp) {
            self.emit(&[0x41, 0x89, 0x45, disp as u8]); // mov dword [r13+disp8], eax
        } else {
            self.emit(&[0x41, 0x89, 0x84, 0x25]); // mov dword [r13+disp32], eax
            self.emit(&disp.to_le_bytes());
        }
    }

    fn emit_mov_dword_to_rcx_disp(&mut self, disp: i32) {
        if (-128..=127).contains(&disp) {
            self.emit(&[0x89, 0x41, disp as u8]); // mov dword [rcx+disp8], eax
        } else {
            self.emit(&[0x89, 0x81]); // mov dword [rcx+disp32], eax
            self.emit(&disp.to_le_bytes());
        }
    }

    fn emit_mov_dword_from_rcx_disp(&mut self, disp: i32) {
        if (-128..=127).contains(&disp) {
            self.emit(&[0x8B, 0x41, disp as u8]); // mov eax, dword [rcx+disp8]
        } else {
            self.emit(&[0x8B, 0x81]); // mov eax, dword [rcx+disp32]
            self.emit(&disp.to_le_bytes());
        }
    }

    fn emit_mov_dword_to_rbp_disp(&mut self, disp: i32) {
        if (-128..=127).contains(&disp) {
            self.emit(&[0x89, 0x45, disp as u8]); // mov dword [rbp+disp8], eax
        } else {
            self.emit(&[0x89, 0x85]); // mov dword [rbp+disp32], eax
            self.emit(&disp.to_le_bytes());
        }
    }

    fn emit_mov_dword_from_rbp_disp(&mut self, disp: i32) {
        if (-128..=127).contains(&disp) {
            self.emit(&[0x8B, 0x45, disp as u8]); // mov eax, dword [rbp+disp8]
        } else {
            self.emit(&[0x8B, 0x85]); // mov eax, dword [rbp+disp32]
            self.emit(&disp.to_le_bytes());
        }
    }

    fn emit_mov_word_to_rbp_from_r8(&mut self, disp: i32) {
        debug_assert!(!(-128..=127).contains(&disp));
        // mov [rbp+disp32], r8w — REX.R for r8; disp32 required for slots like -0x120
        self.emit(&[0x66, 0x44, 0x89, 0x85]);
        self.emit(&disp.to_le_bytes());
    }

    fn emit_mov_word_imm_to_rbp(&mut self, disp: i32, imm: u16) {
        debug_assert!(!(-128..=127).contains(&disp));
        // mov word [rbp+disp32], imm16
        self.emit(&[0x66, 0xC7, 0x85]);
        self.emit(&disp.to_le_bytes());
        self.emit(&imm.to_le_bytes());
    }

    fn emit_movzx_word_from_rbp_to_eax(&mut self, disp: i32) {
        debug_assert!(!(-128..=127).contains(&disp));
        // movzx eax, word [rbp+disp32]
        self.emit(&[0x66, 0x0F, 0xB7, 0x85]);
        self.emit(&disp.to_le_bytes());
    }

    fn emit_mov_qword_from_rbp_to_reg(&mut self, reg: u8, disp: i32) {
        let rex = if reg >= 8 { 0x4C } else { 0x48 };
        let reg = reg & 7;
        if (-128..=127).contains(&disp) {
            self.emit(&[rex, 0x8B, (reg << 3) | 0x45, disp as u8]);
        } else {
            self.emit(&[rex, 0x8B, (reg << 3) | 0x85]);
            self.emit(&disp.to_le_bytes());
        }
    }

    fn emit_mov_qword_to_rbp_from_reg(&mut self, reg: u8, disp: i32) {
        let rex = if reg >= 8 { 0x4C } else { 0x48 };
        let reg = reg & 7;
        if (-128..=127).contains(&disp) {
            self.emit(&[rex, 0x89, (reg << 3) | 0x45, disp as u8]);
        } else {
            self.emit(&[rex, 0x89, (reg << 3) | 0x85]);
            self.emit(&disp.to_le_bytes());
        }
    }

    fn emit_mov_dword_from_r15_spill(&mut self, spill_reg: u8) {
        let disp = (spill_reg as i32) * 8 - 0x80;
        if (-128..=127).contains(&disp) {
            self.emit(&[0x41, 0x8B, 0x47, disp as u8]); // mov eax, dword [r15+disp8]
        } else {
            self.emit(&[0x41, 0x8B, 0x87]); // mov eax, dword [r15+disp32]
            self.emit(&disp.to_le_bytes());
        }
    }

    fn emit_mov_dword_to_r15_spill(&mut self, spill_reg: u8) {
        let disp = (spill_reg as i32) * 8 - 0x80;
        if (-128..=127).contains(&disp) {
            self.emit(&[0x41, 0x89, 0x47, disp as u8]); // mov dword [r15+disp8], eax
        } else {
            self.emit(&[0x41, 0x89, 0x87]); // mov dword [r15+disp32], eax
            self.emit(&disp.to_le_bytes());
        }
    }

    fn emit_handler_run_native(&mut self) {
        self.label("h_run_native");
        self.emit_native_sled_invoke();
    }

    fn emit_handler_bail_native(&mut self) {
        self.label("h_bail_native");
        self.emit_native_sled_invoke();
    }

    /// L4d: read sled offset + orig rva, sync VM spills↔native rbp locals, run sled, resume VM.
    ///
    /// Native locals base: direct lea r14 from `.knvest` `native_stack_top` (no indirect slot).
    /// VM spill base in r15 (callee-saved, captured from vm rbp before rbp switch).
    fn emit_native_sled_invoke(&mut self) {
        let sync_pairs = self.native_sync.clone();
        self.emit(&[0x48, 0x8B, 0x06]); // mov rax, [rsi] sled offset
        self.emit(&[0x49, 0x89, 0xC3]); // mov r11, rax
        self.emit(&[0x48, 0x83, 0xC6, 0x10]); // add rsi, 16 (skip orig rva)
        self.emit(&[0x48, 0x89, 0xB5, 0x68, 0xFF, 0xFF, 0xFF]); // mov [rbp-0x98], rsi
        self.emit_mov_qword_to_rbp_from_reg(5, -0x118); // mov [rbp-0x118], rbp
        self.emit_mov_reg_reg(15, 5); // mov r15, rbp — VM spill base (not r13/rsp)
        self.emit_mov_reg_reg(12, 4); // mov r12, rsp

        self.emit_load_native_locals_base_into_r14();
        self.emit_mov_reg_reg(5, 14); // mov rbp, r14 — native locals before spill sync
        for &(rbp_disp, spill) in &sync_pairs {
            self.emit_mov_dword_from_r15_spill(spill);
            self.emit_mov_dword_to_rbp_disp(rbp_disp);
        }

        // Dedicated call stack above locals within native_stack (Win64 shadow/ret must not
        // overlap [rbp±disp] slots like the loop counter at [rbp-4]).
        self.emit(&[0x48, 0x8D, 0xA5, 0x80, 0x00, 0x00, 0x00]); // lea rsp, [rbp+0x80]
        self.emit(&[0x48, 0x83, 0xE4, 0xF0]); // and rsp, -16
        self.lea_rip_rel32(0x4C, 2, "native_sleds");
        self.emit(&[0x4D, 0x01, 0xDA]); // add r10, r11
        self.emit(&[0x48, 0x83, 0xEC, 0x28]); // sub rsp, 0x28 shadow (rsp%16==8 before call)
        self.emit(&[0x41, 0xFF, 0xD2]); // call r10
        self.emit(&[0x48, 0x83, 0xC4, 0x28]); // add rsp, 0x28

        for &(rbp_disp, spill) in &sync_pairs {
            self.emit_mov_dword_from_rbp_disp(rbp_disp);
            self.emit_mov_dword_to_r15_spill(spill);
        }

        self.emit_mov_reg_reg(5, 15); // mov rbp, r15 — restore VM frame (never via r13)
        self.emit_mov_reg_reg(4, 12); // mov rsp, r12
        self.emit(&[0x48, 0x8B, 0xB5, 0x68, 0xFF, 0xFF, 0xFF]); // mov rsi, [rbp-0x98]
        self.jmp_to_dispatch();
    }

    fn emit_handler_cmp(&mut self) {
        self.label("h_cmp");
        self.emit(&[0x0F, 0xB6, 0x0E]);
        self.emit(&[0x48, 0xFF, 0xC6]);
        self.emit(&[0x0F, 0xB6, 0x3E]);
        self.emit(&[0x48, 0xFF, 0xC6]);
        self.emit(&[0x48, 0x8B, 0x44, 0xCD, 0x80]);
        self.emit(&[0x48, 0x3B, 0x44, 0xFD, 0x80]);
        self.emit(&[0x9C]);
        self.emit(&[0x58]);
        self.emit(&[0x48, 0x25, 0xC1, 0x08, 0x00, 0x00]);
        self.emit(&[0x48, 0x89, 0x85, 0x70, 0xFF, 0xFF, 0xFF]);
        self.jmp_to_dispatch();
    }

    fn emit_handler_cmp32(&mut self) {
        self.label("h_cmp32");
        self.emit(&[0x0F, 0xB6, 0x0E]);
        self.emit(&[0x48, 0xFF, 0xC6]);
        self.emit(&[0x0F, 0xB6, 0x3E]);
        self.emit(&[0x48, 0xFF, 0xC6]);
        self.emit(&[0x8B, 0x44, 0xCD, 0x80]); // mov eax, dword [rbp+rcx*8-0x80]
        self.emit(&[0x3B, 0x44, 0xFD, 0x80]); // cmp eax, dword [rbp+rdi*8-0x80]
        self.emit(&[0x9C]);
        self.emit(&[0x58]);
        self.emit(&[0x48, 0x25, 0xC1, 0x08, 0x00, 0x00]);
        self.emit(&[0x48, 0x89, 0x85, 0x70, 0xFF, 0xFF, 0xFF]);
        self.jmp_to_dispatch();
    }

    fn emit_handler_jmp(&mut self) {
        self.label("h_jmp");
        self.emit(&[0x48, 0x8B, 0x06]);
        self.emit(&[0x48, 0x83, 0xC6, 0x08]);
        self.lea_rip_rel32(0x48, 6, "bytecode");
        self.emit(&[0x48, 0x01, 0xF0]);
        self.emit(&[0x48, 0x89, 0xC6]);
        self.jmp_to_dispatch();
    }

    fn emit_handler_jmpif(&mut self) {
        self.label("h_jmpif");
        self.emit_jmpif_handler();
        self.jmp_to_dispatch();
    }

    fn emit_handler_call(&mut self) {
        self.label("h_call");
        self.emit(&[0x48, 0x8B, 0x06]);
        self.emit(&[0x48, 0x83, 0xC6, 0x08]);
        self.emit(&[0x48, 0x89, 0xB5, 0x68, 0xFF, 0xFF, 0xFF]);
        self.lea_rip_rel32(0x48, 1, "bytecode");
        self.emit(&[0x48, 0x8B, 0xB5, 0x68, 0xFF, 0xFF, 0xFF]);
        self.emit(&[0x48, 0x29, 0xCE]);
        self.emit(&[0x48, 0x8B, 0x95, 0x38, 0xFF, 0xFF, 0xFF]);
        self.emit_mov_reg_reg(11, 0); // mov r11, rax — preserve callee target offset
        match self.dispatch_mode {
            DispatchMode::Table => {
                self.emit_movzx_word_from_rbp_to_eax(-0x120); // caller bb_id for ret refresh
                self.emit(&[0x48, 0xC1, 0xE0, 0x20]); // shl rax, 32
                self.emit(&[0x48, 0x09, 0xF0]); // or rax, rsi — lo32 = return index
            }
            DispatchMode::Threaded => {
                self.emit_mov_reg_reg(0, 6); // mov rax, rsi — return index only (no L4e bb_id)
            }
        }
        self.emit(&[0x48, 0x89, 0x84, 0xD5, 0x00, 0xFE, 0xFF, 0xFF]); // mov [rbp+rdx*8-0x200], rax
        self.emit(&[0x48, 0xFF, 0xC2]);
        self.emit(&[0x48, 0x89, 0x95, 0x38, 0xFF, 0xFF, 0xFF]);
        self.lea_rip_rel32(0x48, 6, "bytecode");
        self.emit_mov_reg_reg(0, 11); // mov rax, r11
        self.emit(&[0x48, 0x01, 0xF0]);
        self.emit(&[0x48, 0x89, 0xC6]);
        self.jmp_to_dispatch();
    }

    fn emit_handler_ret(&mut self) {
        self.label("h_ret");
        self.emit(&[0x48, 0x8B, 0x85, 0x38, 0xFF, 0xFF, 0xFF]); // mov rax, [rbp-0xC8] call depth
        self.emit(&[0x48, 0xFF, 0xC8]); // dec rax
        self.emit(&[0x48, 0x89, 0x85, 0x38, 0xFF, 0xFF, 0xFF]); // mov [rbp-0xC8], rax
        self.emit(&[0x48, 0x89, 0xC2]); // mov rdx, rax — ret frame index
        self.emit(&[0x48, 0x8B, 0x84, 0xC5, 0x00, 0xFE, 0xFF, 0xFF]); // mov rax, [rbp+rdx*8-0x200]
        self.emit(&[0x48, 0x89, 0xC3]); // mov rbx, rax — packed ret words
        self.emit(&[0x48, 0xC1, 0xE8, 0x20]); // shr rax, 32
        self.emit(&[0x44, 0x0F, 0xB7, 0xC0]); // movzx r8d, eax — caller bb_id
        self.emit(&[0x48, 0x89, 0xD8]); // mov rax, rbx
        self.emit(&[0x48, 0x25, 0xFF, 0xFF, 0xFF, 0xFF]); // and eax, 0xFFFFFFFF — return index
        self.lea_rip_rel32(0x48, 6, "bytecode"); // lea rsi, [bytecode]
        self.emit(&[0x48, 0x01, 0xF0]); // add rax, rsi — return bytecode pointer
        self.emit(&[0x48, 0x89, 0xC6]); // mov rsi, rax
        match self.dispatch_mode {
            DispatchMode::Table => self.jmp_rel32("h_set_block_map_resolve"),
            DispatchMode::Threaded => self.jmp_to_dispatch(),
        }
    }

    fn emit_handler_native_call(&mut self) {
        self.label("h_native_call");
        self.emit_native_call_handler();
        self.jmp_to_dispatch();
    }

    fn emit_handler_push(&mut self) {
        self.label("h_push");
        self.emit(&[0x0F, 0xB6, 0x0E]);
        self.emit(&[0x48, 0xFF, 0xC6]);
        self.emit(&[0x48, 0x8B, 0x44, 0xCD, 0x80]);
        self.emit(&[0x48, 0x8B, 0x95, 0x18, 0xFF, 0xFF, 0xFF]);
        self.emit(&[0x48, 0x89, 0x84, 0xD5, 0x80, 0xFC, 0xFF, 0xFF]);
        self.emit(&[0x48, 0xFF, 0xC2]);
        self.emit(&[0x48, 0x89, 0x95, 0x18, 0xFF, 0xFF, 0xFF]);
        self.jmp_to_dispatch();
    }

    fn emit_handler_pop(&mut self) {
        self.label("h_pop");
        self.emit(&[0x0F, 0xB6, 0x0E]);
        self.emit(&[0x48, 0xFF, 0xC6]);
        self.emit(&[0x48, 0x8B, 0x95, 0x18, 0xFF, 0xFF, 0xFF]);
        self.emit(&[0x48, 0xFF, 0xCA]);
        self.emit(&[0x48, 0x89, 0x95, 0x18, 0xFF, 0xFF, 0xFF]);
        self.emit(&[0x48, 0x8B, 0x84, 0xD5, 0x80, 0xFC, 0xFF, 0xFF]);
        self.emit(&[0x48, 0x89, 0x44, 0xCD, 0x80]);
        self.jmp_to_dispatch();
    }

    fn emit_handler_load_byte(&mut self) {
        self.label("h_load_byte");
        self.emit(&[0x0F, 0xB6, 0x0E]);
        self.emit(&[0x48, 0xFF, 0xC6]);
        self.emit(&[0x0F, 0xB6, 0x3E]);
        self.emit(&[0x48, 0xFF, 0xC6]);
        self.emit(&[0x48, 0x8B, 0x44, 0xFD, 0x80]);
        self.lea_rip_rel32(0x48, 2, "bytecode");
        self.emit(&[0x48, 0x01, 0xD0]);
        self.emit(&[0x0F, 0xB6, 0x00]);
        self.emit(&[0x48, 0x89, 0x44, 0xCD, 0x80]);
        self.jmp_to_dispatch();
    }

    fn emit_handler_exit(&mut self) {
        self.label("h_exit");
        self.emit(&[0x0F, 0xB6, 0x0E]);
        self.emit(&[0x48, 0x8B, 0x4C, 0xCD, 0x80]);
        self.emit(&[0x48, 0x83, 0xEC, 0x20]);
        self.emit(&[0xFF, 0x95, 0x58, 0xFF, 0xFF, 0xFF]);
        self.emit(&[0x48, 0x83, 0xC4, 0x20]);
        self.emit(&[0xC3]);
    }

    fn emit_jmpif_handler(&mut self) {
        self.emit(&[0x0F, 0xB6, 0x0E]);
        self.emit(&[0x48, 0xFF, 0xC6]);
        self.emit(&[0x48, 0x8B, 0x06]);
        self.emit(&[0x48, 0x83, 0xC6, 0x08]);
        self.emit(&[0x48, 0x89, 0xC3]);

        self.emit(&[0x83, 0xF9, 0x01]);
        self.jcc_rel32(0x85, "jmpif_chk2");
        self.emit_push_flags_and_jcc(0x84);
        self.label("jmpif_chk2");

        self.emit(&[0x83, 0xF9, 0x02]);
        self.jcc_rel32(0x85, "jmpif_chk3");
        self.emit_push_flags_and_jcc(0x85);
        self.label("jmpif_chk3");

        self.emit(&[0x83, 0xF9, 0x03]);
        self.jcc_rel32(0x85, "jmpif_chk4");
        self.emit_push_flags_and_jcc(0x8F);
        self.label("jmpif_chk4");

        self.emit(&[0x83, 0xF9, 0x04]);
        self.jcc_rel32(0x85, "jmpif_chk5");
        self.emit_push_flags_and_jcc(0x8C);
        self.label("jmpif_chk5");

        self.emit(&[0x83, 0xF9, 0x05]);
        self.jcc_rel32(0x85, "jmpif_chk6");
        self.emit_push_flags_and_jcc(0x8E);
        self.label("jmpif_chk6");

        self.emit(&[0x83, 0xF9, 0x06]);
        self.jcc_rel32(0x85, "jmpif_not_taken");
        self.emit_push_flags_and_jcc(0x8D);

        self.label("jmpif_not_taken");
        self.jmp_to_dispatch();

        self.label("jmpif_taken");
        self.lea_rip_rel32(0x48, 6, "bytecode");
        self.emit(&[0x48, 0x01, 0xDE]);
        self.jmp_to_dispatch();
    }

    fn emit_push_flags_and_jcc(&mut self, jcc: u8) {
        self.emit(&[0xFF, 0xB5, 0x70, 0xFF, 0xFF, 0xFF]);
        self.emit(&[0x9D]);
        self.jcc_rel32(jcc, "jmpif_taken");
        self.jmp_rel32("jmpif_not_taken");
    }

    fn emit_native_call_handler(&mut self) {
        self.emit(&[0x48, 0x8B, 0x06]);
        self.emit(&[0x48, 0x83, 0xC6, 0x08]);
        // Save bytecode pointer past func id at L2 rsi slot [rbp-0x98].
        self.emit(&[0x48, 0x89, 0xB5, 0x68, 0xFF, 0xFF, 0xFF]);

        // IAT win64 ABI path when func_id >= 0x100000000
        self.emit(&[0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]); // mov rcx, 0x100000000
        self.emit(&[0x48, 0x39, 0xC8]); // cmp rax, rcx
        self.jcc_rel32(0x83, "nc_iat"); // jae nc_iat

        self.emit(&[0x48, 0x83, 0xF8, 0x01]);
        self.jcc_rel32(0x84, "nc_func1");
        self.emit(&[0x48, 0x83, 0xF8, 0x03]);
        self.jcc_rel32(0x84, "nc_func3");

        self.label("nc_func2");
        self.emit(&[0x48, 0x8B, 0x45, 0x90]); // VM r2 at [rbp-0x70] (disp8 0x90); lifter leaves int in r2
        self.emit(&[0x48, 0x8D, 0x8D, 0x10, 0xFF, 0xFF, 0xFF]);
        self.emit(&[0x48, 0x3D, 0x64, 0x00, 0x00, 0x00]);
        self.jcc_rel32(0x83, "nc_three_digit");
        self.emit(&[0x48, 0x83, 0xF8, 0x0A]);
        self.jcc_rel32(0x83, "nc_two_digit");
        self.emit(&[0x48, 0x83, 0xC0, 0x30]);
        self.emit(&[0x88, 0x01]);
        self.emit(&[0xC6, 0x41, 0x01, 0x0A]);
        self.emit(&[0x41, 0xB8, 0x02, 0x00, 0x00, 0x00]);
        self.jmp_rel32("nc_write");

        self.label("nc_two_digit");
        self.emit(&[0x48, 0x89, 0xC2]);
        self.emit(&[0xBA, 0x0A, 0x00, 0x00, 0x00]);
        self.emit(&[0x48, 0x89, 0xD3]);
        self.emit(&[0x48, 0x31, 0xD2]);
        self.emit(&[0x48, 0xF7, 0xF3]);
        self.emit(&[0x48, 0x83, 0xC2, 0x30]);
        self.emit(&[0x88, 0x51, 0x01]);
        self.emit(&[0x48, 0x83, 0xC0, 0x30]);
        self.emit(&[0x88, 0x01]);
        self.emit(&[0xC6, 0x41, 0x02, 0x0A]);
        self.emit(&[0x41, 0xB8, 0x03, 0x00, 0x00, 0x00]);
        self.jmp_rel32("nc_write");

        self.label("nc_three_digit");
        self.emit(&[0x48, 0x31, 0xD2]);
        self.emit(&[0xBB, 0x64, 0x00, 0x00, 0x00]);
        self.emit(&[0x48, 0xF7, 0xF3]);
        self.emit(&[0x04, 0x30]);
        self.emit(&[0x88, 0x01]);
        self.emit(&[0x48, 0x89, 0xD0]);
        self.emit(&[0x48, 0x31, 0xD2]);
        self.emit(&[0xBB, 0x0A, 0x00, 0x00, 0x00]);
        self.emit(&[0x48, 0xF7, 0xF3]);
        self.emit(&[0x04, 0x30]);
        self.emit(&[0x88, 0x41, 0x01]);
        self.emit(&[0x80, 0xC2, 0x30]);
        self.emit(&[0x88, 0x51, 0x02]);
        self.emit(&[0xC6, 0x41, 0x03, 0x0A]);
        self.emit(&[0x41, 0xB8, 0x04, 0x00, 0x00, 0x00]);

        self.label("nc_write");
        self.emit(&[0x48, 0x8B, 0x8D, 0x60, 0xFF, 0xFF, 0xFF]);
        self.emit(&[0x48, 0x8D, 0x95, 0x10, 0xFF, 0xFF, 0xFF]);
        self.emit(&[0x4C, 0x8D, 0x8D, 0x30, 0xFF, 0xFF, 0xFF]);
        self.emit(&[0x48, 0x83, 0xEC, 0x28]);
        self.emit(&[0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00]);
        self.emit(&[0xFF, 0x95, 0x50, 0xFF, 0xFF, 0xFF]);
        self.emit(&[0x48, 0x83, 0xC4, 0x28]);
        self.jmp_rel32("nc_done");

        self.label("nc_func1");
        self.emit(&[0x48, 0x8B, 0x8D, 0x60, 0xFF, 0xFF, 0xFF]);
        self.lea_rip_rel32(0x48, 2, "bytecode");
        self.emit(&[0x48, 0x8B, 0x45, 0x80]);
        self.emit(&[0x48, 0x01, 0xD0]);
        self.emit(&[0x48, 0x89, 0xC2]);
        self.emit(&[0x4C, 0x8B, 0x45, 0x88]);
        self.emit(&[0x4C, 0x8D, 0x8D, 0x30, 0xFF, 0xFF, 0xFF]);
        self.emit(&[0x48, 0x83, 0xEC, 0x28]);
        self.emit(&[0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00]);
        self.emit(&[0xFF, 0x95, 0x50, 0xFF, 0xFF, 0xFF]);
        self.emit(&[0x48, 0x83, 0xC4, 0x28]);
        self.jmp_rel32("nc_done");

        self.label("nc_func3");
        self.emit(&[0x48, 0x8B, 0x45, 0x80]);
        self.emit(&[0x48, 0x8D, 0x8D, 0x10, 0xFF, 0xFF, 0xFF]);
        self.emit(&[0x88, 0x01]);
        self.emit(&[0x41, 0xB8, 0x01, 0x00, 0x00, 0x00]);
        self.emit(&[0x48, 0x8B, 0x8D, 0x60, 0xFF, 0xFF, 0xFF]);
        self.emit(&[0x48, 0x8D, 0x95, 0x10, 0xFF, 0xFF, 0xFF]);
        self.emit(&[0x4C, 0x8D, 0x8D, 0x30, 0xFF, 0xFF, 0xFF]);
        self.emit(&[0x48, 0x83, 0xEC, 0x28]);
        self.emit(&[0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00]);
        self.emit(&[0xFF, 0x95, 0x50, 0xFF, 0xFF, 0xFF]);
        self.emit(&[0x48, 0x83, 0xC4, 0x28]);
        self.jmp_rel32("nc_done");

        self.label("nc_iat");
        // rax = func_id; ebx = iat_rva; r11d = low dword (ptr flag in bit 31)
        self.emit(&[0x41, 0x89, 0xC3]); // mov r11d, eax
        self.emit(&[0x44, 0x89, 0xDB]); // mov ebx, r11d (44=REX.R; 41 89 DB is mov r11d,ebx)
        self.emit(&[0x81, 0xE3, 0xFF, 0xFF, 0xFF, 0x7F]); // and ebx, 0x7fffffff
        self.emit(&[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00]); // PEB
        self.emit(&[0x48, 0x8B, 0x40, 0x10]); // ImageBase
        self.emit(&[0x48, 0x01, 0xD8]); // add rax, rbx -> &IAT slot
        self.emit(&[0x48, 0x8B, 0x18]); // mov rbx, [rax] — resolved import (call via rbx)
        // win64 ABI args from VM r0..r3 before ptr test (2151211 putchar order); ptr adds base to rcx.
        self.emit(&[0x41, 0xF7, 0xC3, 0x00, 0x00, 0x00, 0x80]); // test r11d, 0x80000000
        self.jcc_rel32(0x84, "nc_iat_putchar"); // jz — putchar: rcx=r0 only, no rdx/r8/r9
        self.emit(&[0x8B, 0x8D, 0x80, 0xFF, 0xFF, 0xFF]); // mov ecx, [rbp-0x80] offset
        self.emit(&[0x48, 0x8B, 0x95, 0x88, 0xFF, 0xFF, 0xFF]); // rdx <- VM r1 [rbp-0x78]
        self.emit(&[0x4C, 0x8B, 0x85, 0x90, 0xFF, 0xFF, 0xFF]); // r8  <- VM r2 [rbp-0x70]
        self.emit(&[0x4C, 0x8B, 0x8D, 0x98, 0xFF, 0xFF, 0xFF]); // r9  <- VM r3 [rbp-0x68]
        self.lea_rip_rel32(0x48, 0, "bytecode"); // lea rax, [bytecode]
        self.emit(&[0x48, 0x01, 0xC1]); // add rcx, rax (48 01 C1; NOT 49 01 D1 = add r9,rdx)
        self.jmp_rel32("nc_iat_call");
        self.label("nc_iat_putchar");
        self.emit(&[0x8B, 0x8D, 0x80, 0xFF, 0xFF, 0xFF]); // mov ecx, [rbp-0x80] char in VM r0
        self.emit(&[0x83, 0xE1, 0xFF]); // and ecx, 0xff — single-byte putchar arg
        self.label("nc_iat_call");
        // Preserve VM r10..r12 in frame scratch below ret/data stacks (not [-0x200,-0x80]).
        self.emit(&[0x48, 0x8B, 0x85, 0xD0, 0xFF, 0xFF, 0xFF]); // mov rax, [rbp-0x30] VM r10
        self.emit(&[0x48, 0x89, 0x85, 0x00, 0xFB, 0xFF, 0xFF]); // mov [rbp-0x500], rax
        self.emit(&[0x48, 0x8B, 0x85, 0xD8, 0xFF, 0xFF, 0xFF]); // mov rax, [rbp-0x28] VM r11
        self.emit(&[0x48, 0x89, 0x85, 0xF8, 0xFA, 0xFF, 0xFF]); // mov [rbp-0x508], rax
        self.emit(&[0x48, 0x8B, 0x85, 0xE0, 0xFF, 0xFF, 0xFF]); // mov rax, [rbp-0x20] VM r12
        self.emit(&[0x48, 0x89, 0x85, 0xF0, 0xFA, 0xFF, 0xFF]); // mov [rbp-0x510], rax
        self.emit(&[0x48, 0x83, 0xEC, 0x28]);
        self.emit(&[0xFF, 0xD3]); // call rbx
        self.emit(&[0x48, 0x83, 0xC4, 0x28]);
        self.emit(&[0x48, 0x8B, 0x85, 0xF0, 0xFA, 0xFF, 0xFF]); // mov rax, [rbp-0x510]
        self.emit(&[0x48, 0x89, 0x85, 0xE0, 0xFF, 0xFF, 0xFF]); // mov [rbp-0x20], rax
        self.emit(&[0x48, 0x8B, 0x85, 0xF8, 0xFA, 0xFF, 0xFF]); // mov rax, [rbp-0x508]
        self.emit(&[0x48, 0x89, 0x85, 0xD8, 0xFF, 0xFF, 0xFF]); // mov [rbp-0x28], rax
        self.emit(&[0x48, 0x8B, 0x85, 0x00, 0xFB, 0xFF, 0xFF]); // mov rax, [rbp-0x500]
        self.emit(&[0x48, 0x89, 0x85, 0xD0, 0xFF, 0xFF, 0xFF]); // mov [rbp-0x30], rax
        self.jmp_rel32("nc_done");

        self.label("nc_done");
        self.emit(&[0x48, 0x8B, 0xB5, 0x68, 0xFF, 0xFF, 0xFF]);
    }

    fn emit_handler_table_placeholder(&mut self) {
        self.label("handler_table");
        self.handler_table_start = Some(self.pos());
        for _ in 0..256 {
            self.emit(&[0x00, 0x00, 0x00, 0x00]);
        }
    }

    fn fill_handler_table(&mut self) -> HandlerRedirectPlan {
        let table_base = self
            .handler_table_start
            .expect("handler table placeholder missing");
        let mut by_op = [0i32; CANONICAL_OPCODES.len()];
        for (idx, label) in CANONICAL_HANDLER_LABELS.iter().enumerate() {
            by_op[idx] = self.handler_offset(label, table_base);
        }
        let nop_idx = CANONICAL_OPCODES
            .iter()
            .position(|&o| o == crate::vm::OpCode::Nop)
            .unwrap();
        let default_off = by_op[nop_idx];
        let set_map_off = self.handler_offset("h_set_block_map", table_base);
        let handlers = self.opcode_map.handler_table_entries();
        for i in 0..256usize {
            let op = i as u8;
            let off = handlers
                .iter()
                .find(|(hop, _)| *hop == op)
                .map(|(_, label)| self.handler_offset(label, table_base))
                .unwrap_or(default_off);
            let patch_at = table_base + i * 4;
            self.code[patch_at..patch_at + 4].copy_from_slice(&off.to_le_bytes());
        }
        let meta_patch = table_base + (META_WIRE_BYTE as usize) * 4;
        self.code[meta_patch..meta_patch + 4].copy_from_slice(&set_map_off.to_le_bytes());
        HandlerRedirectPlan {
            by_op,
            nop_default: default_off,
            set_block_map: set_map_off,
        }
    }

    fn handler_offset(&self, label: &str, table_base: usize) -> i32 {
        let handler = *self.labels.get(label).unwrap_or(&table_base);
        (handler as i64 - table_base as i64) as i32
    }

    fn emit_strings_and_marker(&mut self, knv5: &[u8], block_map_plan: &BlockMapPlan, native_sleds: &[u8]) {
        self.label("k32_str");
        self.emit(&[
            0x6B, 0x00, 0x65, 0x00, 0x72, 0x00, 0x6E, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x33, 0x00,
            0x32, 0x00, 0x2E, 0x00, 0x64, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x00, 0x00,
        ]);
        self.label("gpa_str");
        self.emit(b"GetProcAddress\0");
        self.label("gsth_str");
        self.emit(b"GetStdHandle\0");
        self.label("wf_str");
        self.emit(b"WriteFile\0");
        self.label("ep_str");
        self.emit(b"ExitProcess\0");

        while self.pos() % 16 != 0 {
            self.emit(&[0xCC]);
        }
        let pack_meta = PackMetadata {
            opcode_map: self.opcode_map.clone(),
            dispatch_mode: self.dispatch_mode,
        };
        self.emit(&pack_meta.to_embedded_bytes());
        self.emit(knv5);
        while self.pos() % 16 != 0 {
            self.emit(&[0xCC]);
        }
        self.label("knv6_block_maps");
        self.knv6_offset = Some(self.pos());
        let knv6_pos = self.pos();
        self.emit(&block_map_plan.to_embedded_bytes());
        self.labels.insert("knv6_count", knv6_pos + 9);
        self.label("exit_wire_cmp_slot");
        self.emit(&[0x00]);
        while self.pos() % 16 != 0 {
            self.emit(&[0xCC]);
        }
        self.label("native_sleds");
        self.emit(native_sleds);
        while self.pos() % 16 != 0 {
            self.emit(&[0xCC]);
        }
        self.label("native_frame_ptr");
        self.emit(&[0x00; 8]);
        self.label("native_stack");
        for _ in 0..0x200 {
            self.emit(&[0x00]);
        }
        self.label("native_stack_top");
        self.emit(b"VMBC");
        self.label("bytecode");
    }

    fn finalize(mut self) -> (Vec<u8>, usize, usize, HandlerRedirectPlan) {
        if let Some(patch_at) = self.exit_cmp_patch_pos {
            let _ = patch_at;
        }
        if let Some(first) = self.block_map_plan.entries.first() {
            if let Some(slot) = self.labels.get("exit_wire_cmp_slot").copied() {
                self.code[slot] = first.exit_wire;
            }
        }
        let handler_plan = self.fill_handler_table();
        let rel32 = std::mem::take(&mut self.rel32);
        for (patch_at, target) in rel32 {
            let tgt = *self.labels.get(target).unwrap_or(&0);
            let next_ip = patch_at + 4;
            let disp = (tgt as i64 - next_ip as i64) as i32;
            self.code[patch_at..patch_at + 4].copy_from_slice(&disp.to_le_bytes());
        }
        let lea_rip = std::mem::take(&mut self.lea_rip);
        for (patch_at, target) in lea_rip {
            let tgt = *self.labels.get(target).unwrap_or(&0);
            let next_ip = patch_at + 4;
            let disp = (tgt as i64 - next_ip as i64) as i32;
            self.code[patch_at..patch_at + 4].copy_from_slice(&disp.to_le_bytes());
        }
        let size = self.code.len();
        let knv6_offset = self
            .knv6_offset
            .or_else(|| self.labels.get("knv6_block_maps").copied())
            .unwrap_or(size);
        (self.code, size, knv6_offset, handler_plan)
    }
}

#[cfg(test)]
mod tests {
    use super::create_vm_interpreter_stub;
    use crate::vm::block_map::{KNV6_ENTRY_SIZE, KNV6_HEADER_SIZE, KNV6_MAGIC};

    /// InLoadOrderModuleList walk must advance `rcx = [rcx]` once per iteration (at
    /// `module_next`), not again at `module_loop` entry — double-advance skips kernel32.
    #[test]
    fn handler_table_live_slots_all_nonzero_with_nop_default() {
        let (stub, _, _, plan) = create_vm_interpreter_stub(
            0,
            0,
            &crate::vm::OpcodeMap::from_seed(0xDEAD_BEEF),
            crate::vm::DispatchMode::Table,
            &[],
            &crate::vm::BlockMapPlan::default(),
            &[],
            &[],
        );
        assert!(
            plan.nop_default >= crate::vm::block_map::HANDLER_REDIRECT_TABLE_SIZE as i32,
            "nop_default must point past redirect table, got {:#x}",
            plan.nop_default
        );
        let table_base = handler_table_base(&stub);
        let mut zero_slots = 0usize;
        for slot in 0..256 {
            let off = i32::from_le_bytes(
                stub[table_base + slot * 4..table_base + slot * 4 + 4]
                    .try_into()
                    .unwrap(),
            );
            if off == 0 {
                zero_slots += 1;
            }
        }
        assert_eq!(
            zero_slots, 0,
            "live handler_table must have no zero slots (dispatch would AV)"
        );
    }

    #[test]
    fn peb_module_walk_single_advance_per_iteration() {
        let (stub, _, _, _) = create_vm_interpreter_stub(0, 0, &crate::vm::OpcodeMap::from_seed(0), crate::vm::DispatchMode::Table, &[], &crate::vm::BlockMapPlan::default(), &[], &[]);
        let init = [0x49u8, 0x8B, 0x0B]; // mov rcx, [r11] — first module
        let done = [0x48u8, 0x8B, 0x59, 0x30]; // name_cmp_done: mov rbx, [rcx+0x30]
        let advance = [0x48u8, 0x8B, 0x09]; // mov rcx, [rcx]

        let start = stub
            .windows(init.len())
            .position(|w| w == init)
            .expect("PEB walk init mov rcx,[r11]");
        let end = stub[start..]
            .windows(done.len())
            .position(|w| w == done)
            .map(|p| start + p)
            .expect("PEB walk name_cmp_done");
        let walk_region = &stub[start..end];
        let advances = walk_region
            .windows(advance.len())
            .filter(|w| *w == advance)
            .count();
        assert_eq!(
            advances, 1,
            "module list walk must contain exactly one mov rcx,[rcx] advance before match"
        );
        assert_ne!(
            &walk_region[init.len()..init.len() + advance.len()],
            advance,
            "module_loop must not advance rcx before comparing the current entry"
        );
    }

    #[test]
    fn set_block_map_points_active_redirect_at_knv6_table() {
        let (stub, _, _, _) = create_vm_interpreter_stub(
            0,
            0,
            &crate::vm::OpcodeMap::from_seed(0),
            crate::vm::DispatchMode::Table,
            &[],
            &crate::vm::BlockMapPlan::default(),
            &[],
            &[],
        );
        let sig = [0x44u8, 0x0F, 0xB7, 0x06];
        let pos = stub
            .windows(sig.len())
            .position(|w| w == sig)
            .expect("h_set_block_map");
        let body = &stub[pos..pos.saturating_add(120).min(stub.len())];
        assert!(
            body.windows(4).any(|w| w == [0x49, 0x8D, 0x47, 0x1C]),
            "h_set_block_map must lea rax,[r15+0x1C] for embedded KNV6 redirect table"
        );
        assert!(
            body.windows(7).any(|w| w == [0x48, 0x89, 0x85, 0xD0, 0xFE, 0xFF, 0xFF]),
            "h_set_block_map must mov [rbp-0x130], rax (D0 FE FF FF disp32)"
        );
        assert!(
            !body.windows(3).any(|w| w == [0x48, 0x89, 0x05]),
            "h_set_block_map must not mov [rip+active_redirect_ptr], rax (Windows PE stale)"
        );
        assert!(
            !body.windows(3).any(|w| w == [0xF3, 0x48, 0xA5]),
            "h_set_block_map must not rep movsq into stub handler_table (Windows write hazard)"
        );
    }

    #[test]
    fn set_block_map_movzx_reads_bb_id_from_rsi_not_r14() {
        let (stub, _, _, _) = create_vm_interpreter_stub(
            0,
            0,
            &crate::vm::OpcodeMap::from_seed(0),
            crate::vm::DispatchMode::Table,
            &[],
            &crate::vm::BlockMapPlan::default(),
            &[],
            &[],
        );
        const CORRECT: [u8; 4] = [0x44, 0x0F, 0xB7, 0x06];
        const WRONG: [u8; 4] = [0x45, 0x0F, 0xB7, 0x06];
        assert!(
            stub.windows(CORRECT.len()).any(|w| w == CORRECT),
            "h_set_block_map must emit movzx r8d,word [rsi] as 44 0f b7 06"
        );
        assert!(
            !stub.windows(WRONG.len()).any(|w| w == WRONG),
            "h_set_block_map must not emit 45 0f b7 06 (REX.B turns [rsi] into [r14])"
        );
    }

    #[test]
    fn set_block_map_records_current_bb_id_in_frame() {
        let mut plan = crate::vm::BlockMapPlan::default();
        plan.record_block(0xDEAD_BEEF, 0);
        let (_scratch, _, _, handler_plan) = create_vm_interpreter_stub(
            0,
            0,
            &crate::vm::OpcodeMap::from_seed(0xDEAD_BEEF),
            crate::vm::DispatchMode::Table,
            &[],
            &plan,
            &[],
            &[],
        );
        plan.fill_handler_tables(&handler_plan);
        let (stub, _, _, _) = create_vm_interpreter_stub(
            0,
            0,
            &crate::vm::OpcodeMap::from_seed(0xDEAD_BEEF),
            crate::vm::DispatchMode::Table,
            &[],
            &plan,
            &[],
            &[],
        );
        let sig = [0x44u8, 0x0F, 0xB7, 0x06];
        let set_map = stub
            .windows(sig.len())
            .position(|w| w == sig)
            .expect("h_set_block_map");
        assert!(
            stub.windows(8).any(|w| w == [0x66, 0x44, 0x89, 0x85, 0xE0, 0xFE, 0xFF, 0xFF]),
            "h_set_block_map must persist bb_id to [rbp-0x120] via disp32 (E0 FE FF FF, not E0 FF FF FF → [rbp-0x20])"
        );
        let body = &stub[set_map..set_map.saturating_add(160).min(stub.len())];
        assert!(
            !body.windows(5).any(|w| w == [0x66, 0x44, 0x89, 0x45, 0xE0]),
            "h_set_block_map must not use disp8 0xE0 (aliases VM r12 at [rbp-0x20])"
        );
        assert!(
            !body.windows(8).any(|w| w == [0x66, 0x44, 0x89, 0x85, 0xE0, 0xFF, 0xFF, 0xFF]),
            "h_set_block_map must not store bb_id at [rbp-0x20] (VM r12 slot)"
        );
    }

    #[test]
    fn h_call_skips_bb_id_frame_read_in_threaded_mode() {
        let (stub, _, _, _) = create_vm_interpreter_stub(
            0,
            0,
            &crate::vm::OpcodeMap::from_seed(0),
            crate::vm::DispatchMode::Threaded,
            &[],
            &crate::vm::BlockMapPlan::default(),
            &[],
            &[],
        );
        assert!(
            !stub
                .windows(8)
                .any(|w| w == [0x66, 0x0F, 0xB7, 0x85, 0xE0, 0xFE, 0xFF, 0xFF]),
            "threaded h_call must not read current_bb_id from [rbp-0x120]"
        );
    }

    #[test]
    fn h_call_saves_caller_bb_id_for_table_ret_restore() {
        let (stub, _, _, _) = create_vm_interpreter_stub(
            0,
            0,
            &crate::vm::OpcodeMap::from_seed(0),
            crate::vm::DispatchMode::Table,
            &[],
            &crate::vm::BlockMapPlan::default(),
            &[],
            &[],
        );
        let save_bb = [
            0x66u8, 0x0F, 0xB7, 0x85, 0xE0, 0xFE, 0xFF, 0xFF, // movzx eax, [rbp-0x120]
            0x48, 0xC1, 0xE0, 0x20, // shl rax, 32
            0x48, 0x09, 0xF0, // or rax, rsi
            0x48, 0x89, 0x84, 0xD5, 0x00, 0xFE, 0xFF, 0xFF, // mov [rbp+rdx*8-0x200], rax
        ];
        assert!(
            stub.windows(save_bb.len()).any(|w| w == save_bb),
            "h_call must pack caller bb_id into hi32 of ret stack slot"
        );
    }

    #[test]
    fn h_ret_skips_block_map_refresh_in_threaded_mode() {
        let (stub, _, _, _) = create_vm_interpreter_stub(
            0,
            0,
            &crate::vm::OpcodeMap::from_seed(0),
            crate::vm::DispatchMode::Threaded,
            &[],
            &crate::vm::BlockMapPlan::default(),
            &[],
            &[],
        );
        let ret_sig = [0x48u8, 0x25, 0xFF, 0xFF, 0xFF, 0xFF];
        let ret_pos = stub
            .windows(ret_sig.len())
            .position(|w| w == ret_sig)
            .expect("h_ret and eax,0xffffffff");
        let after = &stub[ret_pos..ret_pos.saturating_add(48).min(stub.len())];
        let resolve = [0x0Fu8, 0xB7, 0x0D]; // movzx ecx, [rip+knv6_count] — start of resolve
        assert!(
            !after.windows(resolve.len()).any(|w| w == resolve),
            "threaded h_ret must not jmp into h_set_block_map_resolve"
        );
    }

    #[test]
    fn h_ret_restores_block_map_via_knv6_search() {
        let (stub, _, _, _) = create_vm_interpreter_stub(
            0,
            0,
            &crate::vm::OpcodeMap::from_seed(0),
            crate::vm::DispatchMode::Table,
            &[],
            &crate::vm::BlockMapPlan::default(),
            &[],
            &[],
        );
        let ret_restore = [
            0x48u8, 0xC1, 0xE8, 0x20, // shr rax, 32
            0x44, 0x0F, 0xB7, 0xC0, // movzx r8d, eax
        ];
        assert!(
            stub.windows(ret_restore.len()).any(|w| w == ret_restore),
            "h_ret must reload caller bb_id from ret stack"
        );
        assert!(
            stub.contains(&0xE9),
            "h_ret must jmp to h_set_block_map_resolve after rebuilding return rsi"
        );
        let ret_sig = [0x48u8, 0x25, 0xFF, 0xFF, 0xFF, 0xFF]; // and eax, 0xffffffff
        let ret_pos = stub
            .windows(ret_sig.len())
            .position(|w| w == ret_sig)
            .expect("h_ret and eax,0xffffffff");
        let after = &stub[ret_pos..ret_pos.saturating_add(32).min(stub.len())];
        assert!(
            after.contains(&0xE9),
            "h_ret must jmp to h_set_block_map_resolve"
        );
    }

    #[test]
    fn prologue_inits_current_bb_id_slot() {
        let (stub, _, _, _) = create_vm_interpreter_stub(
            0,
            0,
            &crate::vm::OpcodeMap::from_seed(0),
            crate::vm::DispatchMode::Table,
            &[],
            &crate::vm::BlockMapPlan::default(),
            &[],
            &[],
        );
        assert!(
            stub.windows(9)
                .any(|w| w == [0x66, 0xC7, 0x85, 0xE0, 0xFE, 0xFF, 0xFF, 0x00, 0x00]),
            "prologue must zero current bb_id at [rbp-0x120] (E0 FE FF FF, not E0 FF FF FF)"
        );
    }

    #[test]
    fn set_block_map_handler_preserves_bytecode_rsi() {
        let (stub, _, _, _) = create_vm_interpreter_stub(
            0,
            0,
            &crate::vm::OpcodeMap::from_seed(0),
            crate::vm::DispatchMode::Table,
            &[],
            &crate::vm::BlockMapPlan::default(),
            &[],
            &[],
        );
        let sig = [0x44u8, 0x0F, 0xB7, 0x06]; // movzx r8d, word [rsi]
        let pos = stub
            .windows(sig.len())
            .position(|w| w == sig)
            .expect("h_set_block_map");
        let body = &stub[pos..pos.saturating_add(120).min(stub.len())];
        assert!(
            !body.contains(&0x56),
            "h_set_block_map must not push rsi (no in-stub handler-table copy)"
        );
        assert!(
            !body.contains(&0x5E),
            "h_set_block_map must not pop rsi after redirect refresh"
        );
        assert!(
            !body.windows(4).any(|w| w == [0x49, 0x8D, 0x77, 0x1C]),
            "h_set_block_map must not lea rsi,[r15+0x1C] (clobbers bytecode PC)"
        );
        assert!(
            body.windows(4).any(|w| w == [0x49, 0x8D, 0x47, 0x1C]),
            "h_set_block_map must lea rax,[r15+0x1C] without touching bytecode rsi"
        );
        assert!(
            body.windows(4).any(|w| w == [0x66, 0x4D, 0x39, 0x07]),
            "h_set_block_map must linear-search cmp [r15],r8w for entry.bb_id match"
        );
        assert!(
            !body.windows(3).any(|w| w == [0x48, 0x69, 0xC0]),
            "h_set_block_map must not imul-index KNV6 (dense index lands mid-blob on PE)"
        );
    }

    fn resolve_lea_rip(stub: &[u8], lea_pos: usize) -> usize {
        let disp = i32::from_le_bytes(stub[lea_pos + 3..lea_pos + 7].try_into().unwrap());
        ((lea_pos + 7) as i64 + disp as i64) as usize
    }

    #[test]
    fn table_dispatch_uses_active_redirect_ptr_and_r10_add_base() {
        let (stub, _, _, _) = create_vm_interpreter_stub(
            0,
            0,
            &crate::vm::OpcodeMap::from_seed(0),
            crate::vm::DispatchMode::Table,
            &[],
            &crate::vm::BlockMapPlan::default(),
            &[],
            &[],
        );
        let dispatch = stub
            .windows(18)
            .position(|w| {
                w[0..3] == [0x4C, 0x8D, 0x15]
                    && w[7..10] == [0x48, 0x8B, 0x9D]
                    && w[14..18] == [0x48, 0x63, 0x04, 0x83]
            })
            .expect("table dispatch lea r10 + mov rbx,[rbp-0x130] + movsxd");
        assert_eq!(
            stub[dispatch + 18..dispatch + 22],
            [0x4C, 0x01, 0xD0, 0xFF],
            "table dispatch must add handler_table base via r10 then jmp rax"
        );
        let table_base = resolve_lea_rip(&stub, dispatch);
        let prologue_init = stub
            .windows(11)
            .position(|w| w[0..3] == [0x48, 0x8D, 0x05] && w[7..11] == [0x48, 0x89, 0x85, 0xD0])
            .expect("prologue must lea rax,[handler_table] then mov [rbp-0x130], rax");
        assert_eq!(
            resolve_lea_rip(&stub, prologue_init),
            table_base,
            "prologue must point [rbp-0x130] at handler_table before first META"
        );
        assert_eq!(
            &stub[prologue_init + 7..prologue_init + 11],
            [0x48, 0x89, 0x85, 0xD0],
            "prologue redirect slot must use disp32 D0 FE FF FF (-0x130)"
        );
    }

    #[test]
    fn set_block_map_rejects_handler_table_image_below_1024() {
        let (stub, _, _, _) = create_vm_interpreter_stub(
            0,
            0,
            &crate::vm::OpcodeMap::from_seed(0),
            crate::vm::DispatchMode::Table,
            &[],
            &crate::vm::BlockMapPlan::default(),
            &[],
            &[],
        );
        let sig = [0x44u8, 0x0F, 0xB7, 0x06];
        let set_map = stub
            .windows(sig.len())
            .position(|w| w == sig)
            .expect("h_set_block_map");
        let body = &stub[set_map..set_map.saturating_add(160).min(stub.len())];
        assert!(
            body.windows(8).any(|w| w == [0x41, 0x81, 0x7F, 0x1C, 0x00, 0x04, 0x00, 0x00]),
            "h_set_block_map must cmp dword [r15+0x1C],1024 before rep movsq"
        );
    }

    #[test]
    fn knv6_resolve_searches_entry_bb_id_field() {
        let (stub, _, _, _) = create_vm_interpreter_stub(
            0,
            0,
            &crate::vm::OpcodeMap::from_seed(0),
            crate::vm::DispatchMode::Table,
            &[],
            &crate::vm::BlockMapPlan::default(),
            &[],
            &[],
        );
        let sig = [0x44u8, 0x0F, 0xB7, 0x06];
        let set_map = stub
            .windows(sig.len())
            .position(|w| w == sig)
            .expect("h_set_block_map");
        let body = &stub[set_map..set_map.saturating_add(160).min(stub.len())];
        assert!(
            body.windows(4).any(|w| w == [0x66, 0x4D, 0x39, 0x07]),
            "h_set_block_map must cmp word [r15],r8w to locate KNV6 entry header"
        );
        assert!(
            !body.windows(3).any(|w| w == [0x48, 0x69, 0xC0]),
            "h_set_block_map must not imul-index KNV6 entries by bb_id operand"
        );
    }

    #[test]
    fn knv6_search_stride_matches_entry_size() {
        let (stub, _, knv6_offset, _) = create_vm_interpreter_stub(
            0,
            0,
            &crate::vm::OpcodeMap::from_seed(0),
            crate::vm::DispatchMode::Table,
            &[],
            &crate::vm::BlockMapPlan::default(),
            &[],
            &[],
        );
        let stride = KNV6_ENTRY_SIZE as u32;
        let expected = [
            0x49,
            0x81,
            0xC7,
            (stride & 0xFF) as u8,
            ((stride >> 8) & 0xFF) as u8,
            ((stride >> 16) & 0xFF) as u8,
            ((stride >> 24) & 0xFF) as u8,
        ];
        assert!(
            stub.windows(expected.len()).any(|w| w == expected),
            "h_set_block_map search loop must add r15,KNV6_ENTRY_SIZE ({KNV6_ENTRY_SIZE:#x})"
        );
        let header = KNV6_HEADER_SIZE as u32;
        let header_add = [
            0x49,
            0x81,
            0xC7,
            (header & 0xFF) as u8,
            ((header >> 8) & 0xFF) as u8,
            ((header >> 16) & 0xFF) as u8,
            ((header >> 24) & 0xFF) as u8,
        ];
        assert!(
            stub.windows(header_add.len()).any(|w| w == header_add),
            "h_set_block_map must add r15,KNV6_HEADER_SIZE ({KNV6_HEADER_SIZE:#x}) after knv6_block_maps lea"
        );
        let lea_sig = [0x4Du8, 0x8D, 0x3D];
        let lea_pos = stub
            .windows(lea_sig.len())
            .position(|w| w == lea_sig)
            .expect("lea r15,[rip+knv6_block_maps]");
        let target = resolve_lea_rip(&stub, lea_pos);
        assert_eq!(
            target,
            knv6_offset,
            "KNV6 resolve must lea r15 to knv6_block_maps label ({knv6_offset:#x})"
        );
    }

    #[test]
    fn handler_table_redirect_slots_precede_handler_bodies() {
        let (stub, _, _, _) = create_vm_interpreter_stub(
            0,
            0,
            &crate::vm::OpcodeMap::from_seed(0),
            crate::vm::DispatchMode::Table,
            &[],
            &crate::vm::BlockMapPlan::default(),
            &[],
            &[],
        );
        let table_base = handler_table_base(&stub);
        let sig = [0x44u8, 0x0F, 0xB7, 0x06];
        let set_map = stub
            .windows(sig.len())
            .position(|w| w == sig)
            .expect("h_set_block_map");
        assert!(
            table_base < set_map,
            "redirect table must precede handler bodies (table {table_base:#x}, h_set_block_map {set_map:#x})"
        );
    }

    #[test]
    fn knv6_handler_table_slots_resolve_inside_stub() {
        use crate::vm::block_map::{
            validate_handler_table_targets, BlockMapPlan, install_handler_table_in_stub,
        };

        let seed = 0x4C34_4100u64;
        let map = crate::vm::OpcodeMap::from_seed(seed);
        let mut plan = BlockMapPlan {
            decode_key: BlockMapPlan::global_decode_key(seed),
            entries: Vec::new(),
            ..Default::default()
        };
        plan.record_block(seed, 0);
        plan.record_block(seed, 1);
        let (_scratch, _, _, handler_plan) = create_vm_interpreter_stub(
            0,
            0,
            &map,
            crate::vm::DispatchMode::Table,
            &[],
            &plan,
            &[],
            &[],
        );
        plan.fill_handler_tables(&handler_plan);
        let (mut stub, _, knv6_offset, _) = create_vm_interpreter_stub(
            0,
            0,
            &map,
            crate::vm::DispatchMode::Table,
            &[],
            &plan,
            &[],
            &[],
        );
        crate::pe::packer::patch_knv6_in_stub(&mut stub, knv6_offset, &plan);
        crate::pe::packer::patch_runtime_handler_table(&mut stub, &plan);

        let parsed = BlockMapPlan::from_embedded(
            &stub[stub
                .windows(KNV6_MAGIC.len())
                .position(|w| w == KNV6_MAGIC)
                .expect("KNV6")..],
        )
        .expect("parse KNV6");
        assert_eq!(parsed.entries.len(), plan.entries.len());
        for (got, want) in parsed.entries.iter().zip(plan.entries.iter()) {
            assert_eq!(
                got.handler_table, want.handler_table,
                "embedded KNV6 bb_id={} handler_table must match plan",
                want.bb_id
            );
        }

        let table_base = handler_table_base(&stub);
        let load_imm_prologue = [0x0Fu8, 0xB6, 0x0E];
        for entry in &plan.entries {
            let nonzero = entry
                .handler_table
                .chunks_exact(4)
                .filter(|c| *c != [0u8; 4])
                .count();
            assert_eq!(
                nonzero, 256,
                "KNV6 bb_id={} must fill all redirect slots (got {nonzero}/256 nonzero)",
                entry.bb_id
            );
            validate_handler_table_targets(&stub, table_base, &entry.handler_table)
                .unwrap_or_else(|e| panic!("KNV6 bb_id={} invalid: {e}", entry.bb_id));
        }

        // Simulate runtime h_set_block_map refresh for every BB entry.
        for entry in &plan.entries {
            install_handler_table_in_stub(&mut stub, table_base, &entry.handler_table);
            validate_handler_table_targets(&stub, table_base, &entry.handler_table)
                .unwrap_or_else(|e| {
                    panic!(
                        "after simulated set_block_map bb_id={} invalid: {e}",
                        entry.bb_id
                    )
                });
            let load_imm_wire = plan
                .map_for_bb_or_base(entry.bb_id, &map)
                .encode(crate::vm::OpCode::LoadImm) as usize;
            let off = i32::from_le_bytes(
                stub[table_base + load_imm_wire * 4..table_base + load_imm_wire * 4 + 4]
                    .try_into()
                    .unwrap(),
            );
            assert!(
                off > 0,
                "bb_id={} load_imm slot must point forward into stub handlers",
                entry.bb_id
            );
            let target = table_base as i64 + off as i64;
            assert!(
                stub.get(target as usize..target as usize + load_imm_prologue.len())
                    == Some(load_imm_prologue.as_slice()),
                "bb_id={} load_imm wire {load_imm_wire:#x} off {off:#x} must land on h_load_imm prologue",
                entry.bb_id
            );
        }
    }

    #[test]
    fn prologue_init_native_frame_ptr_once() {
        let (stub, _, _, _) = create_vm_interpreter_stub(0, 0, &crate::vm::OpcodeMap::from_seed(0), crate::vm::DispatchMode::Table, &[], &crate::vm::BlockMapPlan::default(), &[], &[]);
        let lea_rax_stack = [0x48u8, 0x8D, 0x05]; // lea rax, [rip+disp]
        let store_abs = [0x48u8, 0x89, 0x05]; // mov [rip+disp], rax
        let lea_rax_count = stub.windows(lea_rax_stack.len()).filter(|w| *w == lea_rax_stack).count();
        assert!(
            lea_rax_count >= 1,
            "prologue must lea rax,[native_stack_top] (modrm reg 0, not rsp=4)"
        );
        assert!(
            !stub.windows(3).any(|w| w == [0x48, 0x8D, 0x25]),
            "must not lea rsp,[rip+disp] for native_stack_top (modrm reg 4 bug)"
        );
        let lea_pos = stub
            .windows(lea_rax_stack.len())
            .position(|w| w == lea_rax_stack)
            .expect("lea rax,[rip+disp]");
        let after = &stub[lea_pos..lea_pos + 32];
        assert!(
            after.windows(3).any(|w| w == [0x48, 0x2D, 0x00]),
            "native frame init must sub rax,0x100 after lea"
        );
        assert!(
            stub.windows(store_abs.len()).any(|w| w == store_abs),
            "prologue must mov [rip+native_frame_ptr], rax"
        );
        assert!(
            !stub.windows(7).any(|w| w == [0x48, 0xC7, 0x85, 0xF0, 0xFE, 0xFF, 0xFF]),
            "must not use spill-adjacent [rbp-0x110] slot for native frame ptr"
        );
    }

    #[test]
    fn run_native_and_bail_share_invoke_without_runtime_alloc() {
        let sync = vec![(-4i32, 10u8)];
        let map = crate::vm::OpcodeMap::from_seed(0x14D0_2026);
        let (stub, _, _, _) = create_vm_interpreter_stub(0, 0, &map, crate::vm::DispatchMode::Table, &[], &crate::vm::BlockMapPlan::default(), &[], &sync);

        let invoke_prologue = [0x48u8, 0x8B, 0x06, 0x49, 0x89, 0xC3];
        let mut invoke_sites = Vec::new();
        for (i, w) in stub.windows(invoke_prologue.len()).enumerate() {
            if w == invoke_prologue {
                invoke_sites.push(i);
            }
        }
        assert_eq!(
            invoke_sites.len(),
            2,
            "h_run_native and h_bail_native must each emit invoke prologue"
        );
        let run_site = invoke_sites[0];
        let bail_site = invoke_sites[1];
        assert!(run_site < bail_site);
        let run_body = &stub[run_site..bail_site];
        assert!(
            !run_body.windows(2).any(|w| w == [0x0F, 0x85]),
            "run_native must not runtime-alloc via jne frame_ready"
        );
        assert!(
            run_body.windows(3).any(|w| w == [0x4C, 0x8D, 0x35]),
            "run_native must lea r14,[rip+native_stack_top] (direct absolute, not indirect slot)"
        );
        assert!(
            !run_body.windows(3).any(|w| w == [0x49, 0x89, 0xE5]),
            "run_native must not use r13 as VM spill base before sync"
        );
    }

    fn run_native_invoke_body(stub: &[u8]) -> (usize, usize) {
        let invoke_prologue = [0x48u8, 0x8B, 0x06, 0x49, 0x89, 0xC3];
        let run_site = stub
            .windows(invoke_prologue.len())
            .position(|w| w == invoke_prologue)
            .expect("h_run_native invoke prologue");
        let bail_site = stub[run_site + 1..]
            .windows(invoke_prologue.len())
            .position(|w| w == invoke_prologue)
            .map(|p| run_site + 1 + p)
            .expect("h_bail_native invoke prologue");
        (run_site, bail_site)
    }

    /// Hard contract: last `mov rbp,r14` immediately precedes pre-sync (only r15 spill loads between).
    #[test]
    fn run_native_pre_sync_byte_order_hard() {
        let sync = vec![(-4i32, 10u8)];
        let map = crate::vm::OpcodeMap::from_seed(0x14D0_2026);
        let sled = [0x83u8, 0x6D, 0xFC, 0x01, 0xC3];
        let (stub, _, _, _) = create_vm_interpreter_stub(0, 0, &map, crate::vm::DispatchMode::Table, &[], &crate::vm::BlockMapPlan::default(), &sled, &sync);
        let (run_site, bail_site) = run_native_invoke_body(&stub);
        let run_body = &stub[run_site..bail_site];
        let call_at = run_body
            .windows(3)
            .position(|w| w == [0x41, 0xFF, 0xD2])
            .expect("call r10");
        let before_call = &run_body[..call_at];
        let mov_rbp_r14 = [0x4Cu8, 0x89, 0xF5];
        let pre_sync_store = [0x89u8, 0x45, 0xFC];
        let sync_at = before_call
            .windows(pre_sync_store.len())
            .position(|w| w == pre_sync_store)
            .expect("pre-sync mov [rbp-4], eax");
        let prefix = &before_call[..sync_at];
        let rbp_at = prefix
            .windows(mov_rbp_r14.len())
            .rposition(|w| w == mov_rbp_r14)
            .expect("mov rbp, r14 before first pre-sync store");
        let between = &prefix[rbp_at + mov_rbp_r14.len()..];
        assert!(
            between.is_empty()
                || between.starts_with(&[0x41, 0x8B, 0x47])
                || between.starts_with(&[0x41, 0x8B, 0x87]),
            "only r15 spill load may appear between mov rbp,r14 and pre-sync (got {between:02x?})"
        );
        assert!(
            prefix.windows(3).any(|w| w == [0x4C, 0x8D, 0x35]),
            "must lea r14,[rip+native_stack_top] before mov rbp,r14"
        );
        assert!(
            !prefix.windows(3).any(|w| w == [0x48, 0x89, 0xCD]),
            "must not mov rbp,rcx before pre-sync"
        );
        assert!(
            !prefix.windows(3).any(|w| w == [0x49, 0x89, 0xE5]),
            "must not mov r13,rbp before pre-sync (use r15 for VM spills)"
        );
        assert!(
            prefix.windows(3).any(|w| w == [0x49, 0x89, 0xEF]),
            "must mov r15,rbp for VM spill base before native rbp switch"
        );
        assert!(
            !prefix.windows(3).any(|w| w == [0x49, 0x89, 0xFD]),
            "must not emit mov r13,rdi (wrong encoding for mov r15,rbp)"
        );
    }

    #[test]
    fn run_native_handler_win64_call_sequence() {
        let sync = vec![(-4i32, 10u8)];
        let map = crate::vm::OpcodeMap::from_seed(0x14D0_2026);
        let (stub, _, _, _) = create_vm_interpreter_stub(0, 0, &map, crate::vm::DispatchMode::Table, &[], &crate::vm::BlockMapPlan::default(), &[], &sync);
        let call_r10 = [0x41u8, 0xFF, 0xD2];
        let call_at = stub
            .windows(call_r10.len())
            .position(|w| w == call_r10)
            .expect("call r10");
        let prefix = &stub[..call_at];
        assert!(
            prefix.windows(3).any(|w| w == [0x4C, 0x89, 0xF5]),
            "mov rbp, r14 before sled call (direct lea r14 from native_stack_top)"
        );
        assert!(
            !prefix.windows(3).any(|w| w == [0x48, 0x89, 0xCD]),
            "must not mov rbp, rcx (rcx may hold VM counter)"
        );
        assert!(
            prefix.windows(3).any(|w| w == [0x4C, 0x8D, 0x35]),
            "must lea r14,[rip+native_stack_top] before native rbp switch"
        );
        assert!(
            !prefix.windows(3).any(|w| w == [0x4C, 0x8B, 0x35]),
            "must not indirect-load native frame via [rip+native_frame_ptr] in handler"
        );
        assert!(
            prefix.windows(7).any(|w| w == [0x48, 0x8D, 0xA5, 0x80, 0x00, 0x00, 0x00]),
            "lea rsp, [rbp+0x80] — call stack above native locals"
        );
        assert!(
            !prefix.windows(4).any(|w| w == [0x48, 0x8D, 0x61, 0x80]),
            "must not lea rsp,[rcx+0x80] (rcx may hold stale VM reg during sync)"
        );
        assert!(
            prefix.windows(4).any(|w| w == [0x48, 0x83, 0xE4, 0xF0]),
            "and rsp, -16 before sled call"
        );
        assert!(
            !prefix.windows(3).any(|w| w == [0x48, 0x89, 0xCC]),
            "must not mov rsp,rcx (Win64 shadow overlaps [rbp-4] locals)"
        );
        assert!(
            prefix.windows(4).any(|w| w == [0x48, 0x83, 0xEC, 0x28]),
            "Win64 0x28 shadow before sled call"
        );
        assert!(
            prefix.windows(3).any(|w| w == [0x4D, 0x01, 0xDA]),
            "lea/add native_sleds offset into r10"
        );
    }

    #[test]
    fn run_native_uses_dword_spill_sync_and_preserves_vm_r0() {
        let sync = vec![(-4i32, 10u8)];
        let map = crate::vm::OpcodeMap::from_seed(0x14D0_2026);
        let sled = [0x83u8, 0x6D, 0xFC, 0x01, 0xC3];
        let (stub, _, _, _) = create_vm_interpreter_stub(0, 0, &map, crate::vm::DispatchMode::Table, &[], &crate::vm::BlockMapPlan::default(), &sled, &sync);
        let invoke_prologue = [0x48u8, 0x8B, 0x06, 0x49, 0x89, 0xC3];
        let run_site = stub
            .windows(invoke_prologue.len())
            .position(|w| w == invoke_prologue)
            .expect("h_run_native invoke prologue");
        let bail_site = stub[run_site + 1..]
            .windows(invoke_prologue.len())
            .position(|w| w == invoke_prologue)
            .map(|p| run_site + 1 + p)
            .expect("h_bail_native invoke prologue");
        let run_body = &stub[run_site..bail_site];
        let call_at = run_body
            .windows(3)
            .position(|w| w == [0x41, 0xFF, 0xD2])
            .expect("call r10 in run_native");
        let before_call = &run_body[..call_at];
        let after_call = &run_body[call_at + 3..];
        assert!(
            before_call.windows(3).any(|w| w == [0x41, 0x8B, 0x47]),
            "pre-sync must use dword load from VM spill via r15"
        );
        assert!(
            !before_call.windows(3).any(|w| w == [0x41, 0x8B, 0x45]),
            "pre-sync must not load VM spills via r13"
        );
        assert!(
            before_call.windows(3).any(|w| w == [0x89, 0x45, 0xFC]),
            "pre-sync must store to native [rbp-4] not [rcx-4]"
        );
        assert!(
            !before_call.windows(3).any(|w| w == [0x89, 0x41, 0xFC]),
            "pre-sync must not store via rcx (may hold VM counter)"
        );
        assert!(
            after_call.windows(3).any(|w| w == [0x41, 0x89, 0x47]),
            "post-sync must use dword store to VM spill via r15"
        );
        assert!(
            after_call.windows(3).any(|w| w == [0x4C, 0x89, 0xFD]),
            "must restore VM frame via mov rbp,r15 (not mov rbp,r13)"
        );
        assert!(
            !after_call.windows(3).any(|w| w == [0x49, 0x89, 0xEF]),
            "must not emit mov r15,rbp after sled (wrong restore encoding)"
        );
        assert!(
            after_call.windows(3).any(|w| w == [0x4C, 0x89, 0xE4]),
            "must restore VM rsp via mov rsp,r12"
        );
        assert!(
            !after_call.windows(3).any(|w| w == [0x49, 0x89, 0xED]),
            "must not restore VM frame via r13 (may equal rsp)"
        );
        // spill reg 0 → [r15-0x80]; must not write rax back into VM r0 after sled.
        assert!(
            !after_call.windows(4).any(|w| w == [0x41, 0x89, 0x47, 0x80]),
            "run_native must not clobber VM r0 via spill slot 0"
        );
    }

    #[test]
    fn run_native_pre_sync_follows_native_frame_setup() {
        let sync = vec![(-4i32, 10u8)];
        let map = crate::vm::OpcodeMap::from_seed(0x14D0_2026);
        let sled = [0x83u8, 0x6D, 0xFC, 0x01, 0xC3];
        let (stub, _, _, _) = create_vm_interpreter_stub(0, 0, &map, crate::vm::DispatchMode::Table, &[], &crate::vm::BlockMapPlan::default(), &sled, &sync);
        let (run_site, bail_site) = run_native_invoke_body(&stub);
        let run_body = &stub[run_site..bail_site];
        let call_at = run_body
            .windows(3)
            .position(|w| w == [0x41, 0xFF, 0xD2])
            .expect("call r10 in run_native");
        let before_call = &run_body[..call_at];
        let save_vm_frame = [0x48u8, 0x89, 0xAD, 0xE8, 0xFE, 0xFF, 0xFF];
        let lea_native = [0x4Cu8, 0x8D, 0x35];
        let mov_r15_rbp = [0x49u8, 0x89, 0xEF];
        let mov_rbp_r14 = [0x4Cu8, 0x89, 0xF5];
        let pre_sync_store = [0x89u8, 0x45, 0xFC];
        assert!(
            run_body.windows(save_vm_frame.len()).any(|w| w == save_vm_frame),
            "handler must persist VM frame at [rbp-0x118] on entry"
        );
        let lea_at = before_call
            .windows(lea_native.len())
            .position(|w| w == lea_native)
            .expect("lea r14,[rip+native_stack_top]");
        let r15_at = before_call
            .windows(mov_r15_rbp.len())
            .position(|w| w == mov_r15_rbp)
            .expect("mov r15,rbp before native switch");
        let rbp_at = before_call
            .windows(mov_rbp_r14.len())
            .position(|w| w == mov_rbp_r14)
            .expect("mov rbp,r14 before pre-sync");
        let sync_at = before_call
            .windows(pre_sync_store.len())
            .position(|w| w == pre_sync_store)
            .expect("pre-sync mov [rbp-4], eax");
        assert!(
            r15_at < lea_at && lea_at < rbp_at && rbp_at < sync_at,
            "r15 capture + lea r14 + mov rbp,r14 must precede spill sync stores"
        );
        assert!(
            !before_call.windows(3).any(|w| w == [0x48, 0x89, 0xCD]),
            "must not mov rbp, rcx before pre-sync"
        );
    }

    #[test]
    fn run_native_r15_spill_base_mov_encoding() {
        let sync = vec![(-4i32, 10u8)];
        let map = crate::vm::OpcodeMap::from_seed(0x14D0_2026);
        let sled = [0x83u8, 0x6D, 0xFC, 0x01, 0xC3];
        let (stub, _, _, _) = create_vm_interpreter_stub(0, 0, &map, crate::vm::DispatchMode::Table, &[], &crate::vm::BlockMapPlan::default(), &sled, &sync);
        let (run_site, bail_site) = run_native_invoke_body(&stub);
        let run_body = &stub[run_site..bail_site];
        let invoke_prologue = [0x48u8, 0x8B, 0x06, 0x49, 0x89, 0xC3];
        let entry = run_body
            .windows(invoke_prologue.len())
            .position(|w| w == invoke_prologue)
            .expect("invoke prologue");
        let spill_load = run_body[entry..]
            .windows(4)
            .position(|w| w == [0x41, 0x8B, 0x47, 0xD0])
            .map(|p| entry + p)
            .expect("mov eax,[r15-0x30] pre-sync spill load");
        let setup = &run_body[entry..spill_load];
        assert!(
            setup.windows(3).any(|w| w == [0x49, 0x89, 0xEF]),
            "handler entry must emit mov r15,rbp (49 89 ef) before first r15 spill load"
        );
        assert!(
            !setup.windows(3).any(|w| w == [0x49, 0x89, 0xFD]),
            "must not emit 49 89 fd (mov r13,rdi) instead of mov r15,rbp"
        );
        let call_at = run_body
            .windows(3)
            .position(|w| w == [0x41, 0xFF, 0xD2])
            .expect("call r10");
        let after_call = &run_body[call_at + 3..];
        assert!(
            after_call.windows(3).any(|w| w == [0x4C, 0x89, 0xFD]),
            "post-sled must restore VM frame via mov rbp,r15 (4c 89 fd)"
        );
        assert!(
            !after_call[..after_call
                .windows(3)
                .position(|w| w == [0x4C, 0x89, 0xFD])
                .expect("restore mov")]
            .windows(3)
            .any(|w| w == [0x49, 0x89, 0xEF]),
            "must not emit mov r15,rbp (49 89 ef) as restore"
        );
    }

    /// Linux-only: gcc harness proves lea rsp,[rbp+0x80] + sub [rbp-4] sled layout works.
    #[cfg(target_os = "linux")]
    #[test]
    fn run_native_layout_linux_gcc_harness() {
        use std::io::Write;
        use std::process::Command;

        let src = r#"
#include <stdio.h>
#include <stdint.h>

extern void invoke_sled(char *frame);

int main(void) {
    _Alignas(16) uint8_t arena[0x200];
    for (int i = 0; i < 0x200; i++) arena[i] = 0;
    char *frame = (char *)(arena + 0x100);
    *(int32_t *)(frame - 4) = 3;
    invoke_sled(frame);
    if (*(int32_t *)(frame - 4) != 2) {
        fprintf(stderr, "expected 2 got %d\n", *(int32_t *)(frame - 4));
        return 1;
    }
    return 0;
}
"#;
        let asm_src = r#"
.globl sled_dec
.globl invoke_sled
sled_dec:
    subl $1, -4(%rbp)
    ret
invoke_sled:
    mov %rsp, %r12
    mov %rbp, %r13
    mov %rdi, %rbp
    lea 0x80(%rdi), %rsp
    and $-16, %rsp
    sub $0x28, %rsp
    call sled_dec
    add $0x28, %rsp
    mov %r13, %rbp
    mov %r12, %rsp
    ret
"#;
        let dir = std::env::temp_dir().join("knvest_run_native_harness");
        let _ = std::fs::create_dir_all(&dir);
        let c_path = dir.join("layout.c");
        let s_path = dir.join("layout.S");
        let exe_path = dir.join("layout");
        {
            let mut f = std::fs::File::create(&c_path).expect("write harness.c");
            f.write_all(src.as_bytes()).expect("write harness source");
            let mut f = std::fs::File::create(&s_path).expect("write harness.S");
            f.write_all(asm_src.as_bytes()).expect("write harness asm");
        }
        let gcc = Command::new("gcc")
            .args([
                "-O0",
                "-fno-stack-protector",
                "-fcf-protection=none",
                "-no-pie",
                c_path.to_str().unwrap(),
                s_path.to_str().unwrap(),
                "-o",
                exe_path.to_str().unwrap(),
            ])
            .output()
            .expect("spawn gcc");
        assert!(
            gcc.status.success(),
            "gcc harness build failed: {}",
            String::from_utf8_lossy(&gcc.stderr)
        );
        let run = Command::new(&exe_path).output().expect("run harness");
        assert!(
            run.status.success(),
            "run_native layout harness failed: {}",
            String::from_utf8_lossy(&run.stderr)
        );
    }

    /// Linux-only: two decrement transitions with lift spill slot (reg 10 → [rbp-0x30]) and stub-equivalent sync.
    #[cfg(target_os = "linux")]
    #[test]
    fn run_native_double_decrement_with_lift_spill_linux() {
        use std::io::Write;
        use std::process::Command;

        let src = r#"
#include <stdio.h>
#include <stdint.h>

extern void sled_dec(void);
extern void invoke_once(char *frame);

int main(void) {
    _Alignas(16) uint8_t arena[0x200];
    for (int i = 0; i < 0x200; i++) arena[i] = 0;
    char *frame = (char *)(arena + 0x100);
    *(int32_t *)(frame - 0x30) = 3;
    for (int pass = 0; pass < 2; pass++) {
        int32_t before = *(int32_t *)(frame - 0x30);
        *(int32_t *)(frame - 4) = before;
        invoke_once(frame);
        *(int32_t *)(frame - 0x30) = *(int32_t *)(frame - 4);
        if (*(int32_t *)(frame - 0x30) != before - 1) {
            fprintf(stderr, "pass %d: expected %d got %d\n", pass, before - 1,
                    *(int32_t *)(frame - 0x30));
            return 1;
        }
    }
    if (*(int32_t *)(frame - 0x30) != 1) {
        fprintf(stderr, "expected final spill 1 got %d\n", *(int32_t *)(frame - 0x30));
        return 1;
    }
    return 0;
}
"#;
        let asm_src = r#"
.globl sled_dec
.globl invoke_once
sled_dec:
    subl $1, -4(%rbp)
    ret
invoke_once:
    mov %rsp, %r12
    mov %rbp, %r13
    mov %rdi, %rbp
    lea 0x80(%rdi), %rsp
    and $-16, %rsp
    sub $0x28, %rsp
    call sled_dec
    add $0x28, %rsp
    mov %r13, %rbp
    mov %r12, %rsp
    ret
"#;
        let dir = std::env::temp_dir().join("knvest_run_native_double_spill");
        let _ = std::fs::create_dir_all(&dir);
        let c_path = dir.join("double_spill.c");
        let s_path = dir.join("double_spill.S");
        let exe_path = dir.join("double_spill");
        {
            let mut f = std::fs::File::create(&c_path).expect("write harness.c");
            f.write_all(src.as_bytes()).expect("write harness source");
            let mut f = std::fs::File::create(&s_path).expect("write harness.S");
            f.write_all(asm_src.as_bytes()).expect("write harness asm");
        }
        let gcc = Command::new("gcc")
            .args([
                "-O0",
                "-fno-stack-protector",
                "-fcf-protection=none",
                "-no-pie",
                c_path.to_str().unwrap(),
                s_path.to_str().unwrap(),
                "-o",
                exe_path.to_str().unwrap(),
            ])
            .output()
            .expect("spawn gcc");
        assert!(
            gcc.status.success(),
            "double spill harness build failed: {}",
            String::from_utf8_lossy(&gcc.stderr)
        );
        let run = Command::new(&exe_path).output().expect("run harness");
        assert!(
            run.status.success(),
            "double decrement spill harness failed: {}",
            String::from_utf8_lossy(&run.stderr)
        );
    }

    #[test]
    fn iat_native_call_threshold_uses_full_mov_rcx_imm64() {
        let (stub, _, _, _) = create_vm_interpreter_stub(0, 0, &crate::vm::OpcodeMap::from_seed(0), crate::vm::DispatchMode::Table, &[], &crate::vm::BlockMapPlan::default(), &[], &[]);
        let pattern = [
            0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // mov rcx, 0x100000000
            0x48, 0x39, 0xC8, // cmp rax, rcx
        ];
        assert!(
            stub.windows(pattern.len()).any(|w| w == pattern),
            "IAT threshold check must use 10-byte mov rcx,imm64 followed by cmp rax,rcx"
        );
        let truncated = [0x48u8, 0xB9, 0x00, 0x00, 0x00, 0x01];
        assert!(
            !stub.windows(truncated.len()).any(|w| w == truncated),
            "stub must not emit truncated 6-byte mov rcx,imm64"
        );
    }

    #[test]
    fn vm_metadata_uses_l2_slots_with_correct_disp32() {
        let (stub, _, _, _) = create_vm_interpreter_stub(0, 0, &crate::vm::OpcodeMap::from_seed(0), crate::vm::DispatchMode::Table, &[], &crate::vm::BlockMapPlan::default(), &[], &[]);
        let call_depth_init = [0x48u8, 0xC7, 0x85, 0x38, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00];
        let push_depth_init = [0x48u8, 0xC7, 0x85, 0x18, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00];
        assert!(
            stub.windows(call_depth_init.len()).any(|w| w == call_depth_init),
            "call depth must init [rbp-0xC8] (38 FF FF FF)"
        );
        assert!(
            stub.windows(push_depth_init.len()).any(|w| w == push_depth_init),
            "push depth must init [rbp-0xE8] (18 FF FF FF)"
        );
        let flags_store = [0x48u8, 0x89, 0x85, 0x70, 0xFF, 0xFF, 0xFF];
        let rsi_save = [0x48u8, 0x89, 0xB5, 0x68, 0xFF, 0xFF, 0xFF];
        assert!(
            stub.windows(flags_store.len()).any(|w| w == flags_store),
            "cmp flags must use [rbp-0x90] (70 FF FF FF)"
        );
        assert!(
            stub.windows(rsi_save.len()).any(|w| w == rsi_save),
            "bytecode rsi must use [rbp-0x98] (68 FF FF FF)"
        );
        // Must not clobber L2 WriteFile out-param or digit buffer.
        let wrong_call_on_bytes_written = [0x48u8, 0xC7, 0x85, 0x30, 0xFF, 0xFF, 0xFF];
        let hcall_on_char_buf = [0x48u8, 0x89, 0xB5, 0x10, 0xFF, 0xFF, 0xFF];
        assert!(
            !stub.windows(wrong_call_on_bytes_written.len()).any(|w| w == wrong_call_on_bytes_written),
            "must not store call depth at [rbp-0xD0] bytes-written slot"
        );
        assert!(
            !stub.windows(hcall_on_char_buf.len()).any(|w| w == hcall_on_char_buf),
            "h_call scratch must not use [rbp-0xF0] char buf"
        );
        // disp32 decode sanity: first byte is NOT the hex offset for negatives below -0x80
        assert_eq!(i32::from_le_bytes([0x38, 0xFF, 0xFF, 0xFF]), -0xC8);
        assert_eq!(i32::from_le_bytes([0x18, 0xFF, 0xFF, 0xFF]), -0xE8);
        assert_eq!(i32::from_le_bytes([0x70, 0xFF, 0xFF, 0xFF]), -0x90);
        assert_eq!(i32::from_le_bytes([0x68, 0xFF, 0xFF, 0xFF]), -0x98);
    }

    #[test]
    fn iat_native_call_maps_x64_rcx_from_vm_reg0() {
        let (stub, _, _, _) = create_vm_interpreter_stub(0, 0, &crate::vm::OpcodeMap::from_seed(0), crate::vm::DispatchMode::Table, &[], &crate::vm::BlockMapPlan::default(), &[], &[]);
        // nc_iat must load win64 rcx from VM r0 slot [rbp-0x80] (zero-extended via mov ecx)
        let rcx_from_r0 = [0x8Bu8, 0x8D, 0x80, 0xFF, 0xFF, 0xFF];
        assert!(
            stub.windows(rcx_from_r0.len()).any(|w| w == rcx_from_r0),
            "IAT path must map x64 rcx from VM register 0"
        );
        let rdx_from_r1 = [0x48u8, 0x8B, 0x95, 0x88, 0xFF, 0xFF, 0xFF];
        assert!(
            stub.windows(rdx_from_r1.len()).any(|w| w == rdx_from_r1),
            "IAT path must map x64 rdx from VM r1 [rbp-0x78] (88 FF FF FF)"
        );
        let rdx_wrong_gap = [0x48u8, 0x8B, 0x95, 0x78, 0xFF, 0xFF, 0xFF];
        assert!(
            !stub.windows(rdx_wrong_gap.len()).any(|w| w == rdx_wrong_gap),
            "IAT rdx must not use 78 FF FF FF ([rbp-0x88] gap, not r1)"
        );
        let ptr_fixup = [0x48u8, 0x01, 0xC1]; // add rcx, rax after lea rax,[bytecode]
        assert!(
            stub.windows(ptr_fixup.len()).any(|w| w == ptr_fixup),
            "IAT ptr path must add bytecode base to rcx via rax (48 01 C1 add rcx,rax)"
        );
        // 49 01 D1 = add r9, rdx (wrong REX); 4C 01 D1 = add rcx, r10 (wrong reg for nc_func1 path)
        let mov_r11d_eax = [0x41u8, 0x89, 0xC3];
        let mov_ebx_r11d = [0x44u8, 0x89, 0xDB];
        for (name, pat) in [
            ("add_r9_rdx", [0x49u8, 0x01, 0xD1]),
            ("add_rcx_r10", [0x4Cu8, 0x01, 0xD1]),
        ] {
            assert!(
                !stub.windows(pat.len()).any(|w| w == pat),
                "nc_iat must not emit {name} ({pat:02x?}) for ptr reloc"
            );
        }
        // nc_iat: test ptr-flag first; putchar jz uses ecx-only path with and ecx,0xff.
        let nc_iat_off = stub
            .windows(mov_r11d_eax.len())
            .position(|w| w == mov_r11d_eax)
            .expect("nc_iat mov r11d,eax");
        let iat_load = [0x48u8, 0x8B, 0x18];
        let after_mov_rbx = stub[nc_iat_off..]
            .windows(iat_load.len())
            .position(|w| w == iat_load)
            .map(|p| nc_iat_off + p + iat_load.len())
            .expect("mov rbx,[rax] in nc_iat");
        let test_r11d = [0x41u8, 0xF7, 0xC3, 0x00, 0x00, 0x00, 0x80];
        assert_eq!(
            &stub[after_mov_rbx..after_mov_rbx + test_r11d.len()],
            test_r11d,
            "nc_iat must test r11d immediately after resolving import"
        );
        let putchar_mask = [0x83u8, 0xE1, 0xFF];
        assert!(
            stub.windows(putchar_mask.len()).any(|w| w == putchar_mask),
            "putchar nc_iat path must and ecx,0xff"
        );
        let rcx_from_r1 = [0x48u8, 0x8B, 0x8D, 0x78, 0xFF, 0xFF, 0xFF];
        assert!(
            !stub.windows(rcx_from_r1.len()).any(|w| w == rcx_from_r1),
            "IAT path must not load rcx from VM r1 (breaks putchar in r0)"
        );
        let r8_from_r2 = [0x4Cu8, 0x8B, 0x85, 0x90, 0xFF, 0xFF, 0xFF];
        assert!(
            stub.windows(r8_from_r2.len()).any(|w| w == r8_from_r2),
            "IAT path must map x64 r8 from VM r2 [rbp-0x70] (90 FF FF FF)"
        );
        let r8_from_flags = [0x4Cu8, 0x8B, 0x85, 0x70, 0xFF, 0xFF, 0xFF];
        assert!(
            !stub.windows(r8_from_flags.len()).any(|w| w == r8_from_flags),
            "IAT path must not load r8 from cmp flags slot [rbp-0x90] (70 FF FF FF)"
        );
        let r9_from_r3 = [0x4Cu8, 0x8B, 0x8D, 0x98, 0xFF, 0xFF, 0xFF];
        assert!(
            stub.windows(r9_from_r3.len()).any(|w| w == r9_from_r3),
            "IAT path must map x64 r9 from VM r3 [rbp-0x68] (98 FF FF FF)"
        );
        let r9_from_stdout = [0x4Cu8, 0x8B, 0x8D, 0x60, 0xFF, 0xFF, 0xFF];
        assert!(
            !stub.windows(r9_from_stdout.len()).any(|w| w == r9_from_stdout),
            "IAT path must not load r9 from stdout slot [rbp-0xA0]"
        );
        let iat_call = [0xFFu8, 0xD3]; // call rbx
        let wrong_mov_r11d_ebx = [0x41u8, 0x89, 0xDB];
        assert!(
            stub.windows(iat_load.len()).any(|w| w == iat_load),
            "nc_iat must load resolved import with mov rbx,[rax]"
        );
        assert!(
            stub.windows(iat_call.len()).any(|w| w == iat_call),
            "nc_iat must call through rbx (FF D3), not rax"
        );
        // Byte-exact nc_iat prologue: eax→r11d, then ebx←r11d (not reversed)
        assert_eq!(
            &stub[nc_iat_off + mov_r11d_eax.len()..nc_iat_off + mov_r11d_eax.len() + mov_ebx_r11d.len()],
            mov_ebx_r11d,
            "after mov r11d,eax nc_iat must emit 44 89 DB (mov ebx,r11d)"
        );
        assert!(
            !stub.windows(wrong_mov_r11d_ebx.len()).any(|w| w == wrong_mov_r11d_ebx),
            "must not emit 41 89 DB (mov r11d,ebx) after copying func_id low dword"
        );
        assert!(
            !stub.windows([0xFFu8, 0xD0].len()).any(|w| w == [0xFF, 0xD0]),
            "stub must not use call rax (FF D0) — IAT target lives in rbx"
        );
    }

    fn vm_reg_slot_disp32(reg: u8) -> [u8; 4] {
        ((i32::from(reg) * 8) - 0x80).to_le_bytes()
    }

    /// Metadata (push/call depth, flags, rsi save) must not use VM r0..r15 frame slots.
    #[test]
    fn vm_stub_metadata_must_not_alias_vm_reg_slots() {
        let (stub, _, _, _) = create_vm_interpreter_stub(0, 0, &crate::vm::OpcodeMap::from_seed(0), crate::vm::DispatchMode::Table, &[], &crate::vm::BlockMapPlan::default(), &[], &[]);
        let r13_slot = vm_reg_slot_disp32(13); // E8 FF FF FF = [rbp-0x18]
        assert!(
            !stub.windows(4).any(|w| w == r13_slot),
            "stub must not use r13 slot disp E8 FF FF FF (fact push depth collision)"
        );
        assert!(
            !stub.windows(7).any(|w| w == [0x48, 0xC7, 0x85, 0x30, 0xFF, 0xFF, 0xFF]),
            "must not init call depth at [rbp-0xD0] (30 FF)"
        );
        assert!(
            !stub.windows(7).any(|w| w == [0x48, 0xC7, 0x85, 0x28, 0xFF, 0xFF, 0xFF]),
            "must not init push depth at [rbp-0xD8] (28 FF)"
        );
        assert!(
            !stub.windows(7).any(|w| w == [0x48, 0x89, 0xB5, 0x10, 0xFF, 0xFF, 0xFF]),
            "h_call scratch must not use char buf [rbp-0xF0] (10 FF)"
        );
        assert!(
            !stub.windows(7).any(|w| w == [0x48, 0xC7, 0x85, 0xA8, 0xFF, 0xFF, 0xFF]),
            "must not init call depth at VM r5 slot (A8 FF)"
        );
        assert!(
            !stub.windows(4).any(|w| w == [0xB0, 0xFF, 0xFF, 0xFF]),
            "must not use push depth at VM r6 slot (B0 FF)"
        );
        // push depth: only 18 FF FF FF; call depth: only 38 FF FF FF
        let push_depth = [0x18u8, 0xFF, 0xFF, 0xFF];
        let call_depth = [0x38u8, 0xFF, 0xFF, 0xFF];
        assert!(
            stub.windows(push_depth.len()).filter(|w| *w == push_depth).count() >= 4,
            "h_push/h_pop must reference push depth [rbp-0xE8] (18 FF FF FF)"
        );
        assert!(
            stub.windows(call_depth.len()).filter(|w| *w == call_depth).count() >= 4,
            "h_call/h_ret must reference call depth [rbp-0xC8] (38 FF FF FF)"
        );
        // nc2 reads VM r2 (arith/loop/call/str leave printed int in r2 before nc2)
        let nc2_from_r2 = [0x48u8, 0x8B, 0x45, 0x90];
        assert!(
            stub.windows(nc2_from_r2.len()).any(|w| w == nc2_from_r2),
            "nc_func2 must load integer from VM r2 [rbp-0x70] (45 90)"
        );
        // fact(5): 4 pushes × 4 frames → idx 16 at [rbp-0x300]; ret[0] at [rbp-0x200]
        let data_stack_disp = [0x80u8, 0xFC, 0xFF, 0xFF];
        assert_eq!(i32::from_le_bytes(data_stack_disp), -0x380);
        assert!(
            stub.windows(data_stack_disp.len()).filter(|w| *w == data_stack_disp).count() >= 2,
            "h_push/h_pop data stack must use [rbp-0x380] (80 FC FF FF)"
        );
        assert!(
            !stub.windows(8).any(|w| w == [0x48, 0x89, 0x84, 0xD5, 0x80, 0xF6, 0xFF, 0xFF])
                && !stub.windows(8).any(|w| w == [0x48, 0x8B, 0x84, 0xD5, 0x80, 0xF6, 0xFF, 0xFF]),
            "data stack push/pop must not use [rbp-0x980] (80 F6 FF FF — out of frame)"
        );
        assert!(
            !stub.windows(4).any(|w| w == [0x80, 0xFB, 0xFF, 0xFF]),
            "data stack must not use [rbp-0x480] (out of frame)"
        );
        assert!(
            !stub.windows(4).any(|w| w == [0x80, 0xFD, 0xFF, 0xFF]),
            "data stack must not use old [rbp-0x280] base (aliases ret at idx 16)"
        );
        let prologue_alloc = [0x48u8, 0x81, 0xEC, 0x20, 0x05, 0x00, 0x00];
        assert!(
            stub.windows(prologue_alloc.len()).any(|w| w == prologue_alloc),
            "prologue must allocate >= 0x520 bytes (ret/data/nc_iat scratch)"
        );
        let qword_cmp = [0x48u8, 0x8B, 0x44, 0xCD, 0x80, 0x48, 0x3B, 0x44, 0xFD, 0x80];
        assert!(
            stub.windows(qword_cmp.len()).any(|w| w == qword_cmp),
            "h_cmp must use 64-bit qword compare (fact/loop JG depend on this)"
        );
        let dword_cmp32 = [0x8Bu8, 0x44, 0xCD, 0x80, 0x3B, 0x44, 0xFD, 0x80];
        assert!(
            stub.windows(dword_cmp32.len()).any(|w| w == dword_cmp32),
            "h_cmp32 must use SIB scale*8 (CD/FD) for dword [rbp+reg*8-0x80], not scale*4 (8D/BD)"
        );
        assert!(
            !stub.windows(4).any(|w| w == [0x8B, 0x44, 0x8D, 0x80]),
            "h_cmp32 must not use scale*4 SIB 8D on src (reads wrong VM slot, e.g. r10→r5)"
        );
        assert!(
            !stub.windows(4).any(|w| w == [0x3B, 0x44, 0xBD, 0x80]),
            "h_cmp32 must not use scale*4 SIB BD on dst (reads wrong VM slot, e.g. r15→[rbp-0x44])"
        );
        let cmp32_flags = [
            0x8B, 0x44, 0xCD, 0x80, 0x3B, 0x44, 0xFD, 0x80, 0x9C, 0x58, 0x48, 0x25, 0xC1, 0x08,
            0x00, 0x00, 0x48, 0x89, 0x85, 0x70, 0xFF, 0xFF, 0xFF,
        ];
        assert!(
            stub.windows(cmp32_flags.len()).any(|w| w == cmp32_flags),
            "h_cmp32 must store masked flags to [rbp-0x90] after dword cmp (same path as h_cmp)"
        );
        let spill_save_r10 = [0x48u8, 0x8B, 0x85, 0xD0, 0xFF, 0xFF, 0xFF, 0x48, 0x89, 0x85, 0x00, 0xFB, 0xFF, 0xFF];
        assert!(
            stub.windows(spill_save_r10.len()).any(|w| w == spill_save_r10),
            "nc_iat_call must save VM r10 to frame scratch [rbp-0x500] before external call"
        );
        let spill_restore_r10 = [0x48u8, 0x8B, 0x85, 0x00, 0xFB, 0xFF, 0xFF, 0x48, 0x89, 0x85, 0xD0, 0xFF, 0xFF, 0xFF];
        assert!(
            stub.windows(spill_restore_r10.len()).any(|w| w == spill_restore_r10),
            "nc_iat_call must restore VM r10 from frame scratch after external call"
        );
        assert!(
            !stub.windows(3).any(|w| w == [0xFF, 0x75, 0xD0])
                && !stub.windows(3).any(|w| w == [0x8F, 0x45, 0xD0]),
            "nc_iat_call must not spill VM regs on CPU stack (CRT clobbers above shadow)"
        );
        // nc_iat scratch: decode disp32 as signed i32 (00 FB = -0x500, not 00 FD = -0x300).
        assert_eq!(i32::from_le_bytes([0x00, 0xFB, 0xFF, 0xFF]), -0x500);
        assert_eq!(i32::from_le_bytes([0xF8, 0xFA, 0xFF, 0xFF]), -0x508);
        assert_eq!(i32::from_le_bytes([0xF0, 0xFA, 0xFF, 0xFF]), -0x510);
        let scratch_disps: [[u8; 4]; 3] = [
            (-0x500i32).to_le_bytes(),
            (-0x508i32).to_le_bytes(),
            (-0x510i32).to_le_bytes(),
        ];
        for disp in scratch_disps {
            assert!(
                stub.windows(7)
                    .any(|w| w[0] == 0x48 && (w[1] == 0x89 || w[1] == 0x8B) && w[2] == 0x85 && w[3..7] == disp),
                "nc_iat scratch must use [rbp-0x500..-0x510], missing disp {:?} ({})",
                disp,
                i32::from_le_bytes(disp)
            );
        }
        let forbidden_scratch: [[u8; 4]; 3] = [
            [0x00, 0xFD, 0xFF, 0xFF], // -0x300 data-stack band
            [0x08, 0xFD, 0xFF, 0xFF], // -0x2F8
            [0x10, 0xFD, 0xFF, 0xFF], // -0x2F0
        ];
        for bad in forbidden_scratch {
            assert!(
                !stub.windows(7).any(|w| {
                    w[0] == 0x48
                        && (w[1] == 0x89 || w[1] == 0x8B)
                        && w[2] == 0x85
                        && w[3..7] == bad
                }),
                "nc_iat scratch must not use FD-band disp {:?} (decoded {})",
                bad,
                i32::from_le_bytes(bad)
            );
        }
        let ret_stack_band: [[u8; 4]; 3] = [
            [0xE8, 0xFE, 0xFF, 0xFF], // -0x1E8 depth 3
            [0xE0, 0xFE, 0xFF, 0xFF], // -0x1E0 depth 4
            [0xD8, 0xFE, 0xFF, 0xFF], // -0x1D8 depth 5
        ];
        for bad in ret_stack_band {
            assert!(
                !stub.windows(7).any(|w| {
                    w[0] == 0x48
                        && (w[1] == 0x89 || w[1] == 0x8B)
                        && w[2] == 0x85
                        && w[3..7] == bad
                }),
                "nc_iat scratch must not use ret-stack band disp {bad:02x?} ([rbp-0x200..-0x80])"
            );
        }
        // nc_iat resolve sequence must stay intact (no r12–r14 spill in prologue).
        let iat_resolve = [
            0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, // PEB
            0x48, 0x8B, 0x40, 0x10, // ImageBase
            0x48, 0x01, 0xD8, // add rax, rbx
            0x48, 0x8B, 0x18, // mov rbx, [rax]
        ];
        assert!(
            stub.windows(iat_resolve.len()).any(|w| w == iat_resolve),
            "nc_iat ImageBase/IAT/rbx resolve sequence must be unchanged"
        );
        assert!(
            !stub.windows(4).any(|w| w == [0x49, 0x8B, 0x65, 0xD0])
                && !stub.windows(4).any(|w| w == [0x4C, 0x8B, 0x65, 0xD0]),
            "nc_iat_call must not spill via r12 (clashes with IAT path)"
        );
    }

    /// Mirrors stub addressing: reg n → [rbp+n*8-0x80], data stack idx → [rbp+idx*8-0x380].
    #[derive(Default)]
    struct StubFrame {
        slots: std::collections::HashMap<i32, u64>,
    }

    impl StubFrame {
        fn reg_slot(reg: u8) -> i32 {
            i32::from(reg) * 8 - 0x80
        }

        fn data_slot(idx: i32) -> i32 {
            idx * 8 - 0x380
        }

        fn get(&self, disp: i32) -> u64 {
            self.slots.get(&disp).copied().unwrap_or(0)
        }

        fn set(&mut self, disp: i32, val: u64) {
            self.slots.insert(disp, val);
        }

        fn stub_push(&mut self, reg: u8) {
            let val = self.get(Self::reg_slot(reg));
            let depth = self.get(-0xE8) as i32;
            self.set(Self::data_slot(depth), val);
            self.set(-0xE8, (depth + 1) as u64);
        }

        fn stub_pop(&mut self, reg: u8) {
            let mut depth = self.get(-0xE8) as i32;
            depth -= 1;
            self.set(-0xE8, depth as u64);
            let val = self.get(Self::data_slot(depth));
            self.set(Self::reg_slot(reg), val);
        }

        fn nc_iat_preserve_r10_r12(&mut self) {
            self.set(-0x500, self.get(Self::reg_slot(10)));
            self.set(-0x508, self.get(Self::reg_slot(11)));
            self.set(-0x510, self.get(Self::reg_slot(12)));
        }

        fn nc_iat_restore_r10_r12(&mut self) {
            self.set(Self::reg_slot(12), self.get(-0x510));
            self.set(Self::reg_slot(11), self.get(-0x508));
            self.set(Self::reg_slot(10), self.get(-0x500));
        }
    }

    fn scale_from_sib(sib: u8) -> u8 {
        1 << ((sib >> 6) & 3)
    }

    /// Every SIB used for VM reg [rbp+idx*scale-0x80] in handlers must be scale*8 (CD/FD/D5).
    #[test]
    fn vm_reg_sib_must_be_scale8_in_handlers() {
        let (stub, _, _, _) = create_vm_interpreter_stub(0, 0, &crate::vm::OpcodeMap::from_seed(0), crate::vm::DispatchMode::Table, &[], &crate::vm::BlockMapPlan::default(), &[], &[]);
        let forbidden_sib = [
            (0x8D, "rcx scale*4"),
            (0xBD, "rdi scale*4"),
            (0x95, "rdx scale*4"),
        ];
        for (sib, name) in forbidden_sib {
            assert_eq!(scale_from_sib(sib), 4, "{name} must be scale*4 sentinel");
            for prefix in [0x8Bu8, 0x89, 0x03, 0x2B, 0x3B] {
                let pat = [prefix, 0x44, sib, 0x80];
                assert!(
                    !stub.windows(pat.len()).any(|w| w == pat),
                    "handler must not use {name} SIB in {:02x} 44 {:02x} 80 VM reg access",
                    prefix,
                    sib
                );
            }
            let pat_q = [0x48, 0x8B, 0x44, sib, 0x80];
            assert!(
                !stub.windows(pat_q.len()).any(|w| w == pat_q),
                "handler must not use {name} in qword VM reg load"
            );
            let pat_af = [0x48, 0x0F, 0xAF, 0x44, sib, 0x80];
            assert!(
                !stub.windows(pat_af.len()).any(|w| w == pat_af),
                "handler must not use {name} in imul VM reg access"
            );
        }
        let required: [&[u8]; 7] = [
            &[0x8B, 0x44, 0xCD, 0x80, 0x3B, 0x44, 0xFD, 0x80],
            &[0x48, 0x8B, 0x44, 0xCD, 0x80],
            &[0x48, 0x89, 0x44, 0xCD, 0x80],
            &[0x48, 0x8B, 0x44, 0xFD, 0x80],
            &[0x48, 0x03, 0x44, 0xD5, 0x80],
            &[0x48, 0x89, 0x84, 0xD5, 0x80, 0xFC, 0xFF, 0xFF],
            &[0x48, 0x8B, 0x84, 0xD5, 0x80, 0xFC, 0xFF, 0xFF],
        ];
        for pat in required {
            assert!(
                stub.windows(pat.len()).any(|w| w == pat),
                "missing required scale*8 pattern {:02x?}",
                pat
            );
        }
    }

    /// After main spill push/pop around one putchar, r10 must not pick up r4 (0x10) or depth.
    #[test]
    fn nested_stub_frame_push_pop_preserves_r10_across_putchar_spill() {
        let mut frame = StubFrame::default();
        frame.set(-0xE8, 0);
        frame.set(StubFrame::reg_slot(4), 0x40);
        frame.set(StubFrame::reg_slot(5), 0x40);
        frame.set(StubFrame::reg_slot(10), 1);
        frame.set(StubFrame::reg_slot(11), 2);
        frame.set(StubFrame::reg_slot(12), 3);
        frame.stub_push(5);
        frame.set(StubFrame::reg_slot(4), 0x10); // main sub r4, r4, 0x30

        // One print_char spill trio + callee r5 + nc_iat + restore pops.
        frame.stub_push(10);
        frame.stub_push(11);
        frame.stub_push(12);
        frame.stub_push(5);
        frame.nc_iat_preserve_r10_r12();
        frame.nc_iat_restore_r10_r12();
        frame.stub_pop(5);
        frame.stub_pop(12);
        frame.stub_pop(11);
        frame.stub_pop(10);

        assert_eq!(frame.get(StubFrame::reg_slot(10)), 1);
        assert_eq!(frame.get(StubFrame::reg_slot(11)), 2);
        assert_eq!(frame.get(StubFrame::reg_slot(12)), 3);
        assert_eq!(frame.get(-0xE8), 1, "only main r5 remains on data stack");
        assert_eq!(frame.get(StubFrame::data_slot(1)), 1, "stack[1] holds spilled r10");
    }

    fn handler_table_base(stub: &[u8]) -> usize {
        crate::pe::threaded::handler_table_base(stub)
    }

    fn add_handler_offset(stub: &[u8], map: &crate::vm::OpcodeMap) -> usize {
        let table_base = handler_table_base(stub);
        let wire = map.encode(crate::vm::OpCode::Add) as usize;
        let off = i32::from_le_bytes([
            stub[table_base + wire * 4],
            stub[table_base + wire * 4 + 1],
            stub[table_base + wire * 4 + 2],
            stub[table_base + wire * 4 + 3],
        ]);
        table_base + off as usize
    }

    fn seed_for_add_variant(target: u8) -> u64 {
        for seed in 0..512u64 {
            if crate::vm::OpcodeMap::from_seed(seed).add_handler_variant() == target {
                return seed;
            }
        }
        panic!("no seed yields Add handler variant {target}");
    }

    /// L4b: pack-time seed picks one of several semantically equivalent Add handler bodies.
    #[test]
    fn add_handler_polymorphism_varies_native_bytes_by_seed() {
        use crate::vm::opcode_map::ADD_HANDLER_VARIANT_COUNT;
        let seed_v0 = seed_for_add_variant(0);
        let seed_v1 = seed_for_add_variant(1);
        let map_v0 = crate::vm::OpcodeMap::from_seed(seed_v0);
        let map_v1 = crate::vm::OpcodeMap::from_seed(seed_v1);
        let (stub_v0, _, _, _) = create_vm_interpreter_stub(0, 0, &map_v0, crate::vm::DispatchMode::Table, &[], &crate::vm::BlockMapPlan::default(), &[], &[]);
        let (stub_v1, _, _, _) = create_vm_interpreter_stub(0, 0, &map_v1, crate::vm::DispatchMode::Table, &[], &crate::vm::BlockMapPlan::default(), &[], &[]);

        let h0 = add_handler_offset(&stub_v0, &map_v0);
        let h1 = add_handler_offset(&stub_v1, &map_v1);
        let body_v0 = &stub_v0[h0..h0 + 48];
        let body_v1 = &stub_v1[h1..h1 + 48];
        assert_ne!(body_v0, body_v1, "Add handlers for variant 0 vs 1 must differ");

        let lea_add = [0x48u8, 0x8D, 0x04, 0x03];
        let direct_add = [0x48u8, 0x03, 0x44, 0xD5, 0x80];
        assert!(
            body_v0.windows(direct_add.len()).any(|w| w == direct_add),
            "Add v0 must use direct add rax,[src2]"
        );
        assert!(
            body_v1.windows(lea_add.len()).any(|w| w == lea_add),
            "Add v1 must use lea rax,[rbx+rax]"
        );
        assert!(
            !body_v1.windows(direct_add.len()).any(|w| w == direct_add),
            "Add v1 must not use the v0 direct-add sequence"
        );

        if ADD_HANDLER_VARIANT_COUNT >= 3 {
            let seed_v2 = seed_for_add_variant(2);
            let map_v2 = crate::vm::OpcodeMap::from_seed(seed_v2);
            let (stub_v2, _, _, _) = create_vm_interpreter_stub(0, 0, &map_v2, crate::vm::DispatchMode::Table, &[], &crate::vm::BlockMapPlan::default(), &[], &[]);
            let h2 = add_handler_offset(&stub_v2, &map_v2);
            let body_v2 = &stub_v2[h2..h2 + 48];
            assert_ne!(body_v0, body_v2);
            assert_ne!(body_v1, body_v2);
            // v2 stores partial sum before final add
            let partial_store = [0x48u8, 0x89, 0x44, 0xCD, 0x80, 0x48, 0x8B, 0x44, 0xCD, 0x80];
            assert!(
                body_v2.windows(partial_store.len()).any(|w| w == partial_store),
                "Add v2 must store src1 then reload dst before adding src2"
            );
        }
    }

    #[test]
    fn add_handler_polymorphism_same_seed_is_stable() {
        let seed = seed_for_add_variant(1);
        let map = crate::vm::OpcodeMap::from_seed(seed);
        let (a, _, _, _) = create_vm_interpreter_stub(0, 0, &map, crate::vm::DispatchMode::Table, &[], &crate::vm::BlockMapPlan::default(), &[], &[]);
        let (b, _, _, _) = create_vm_interpreter_stub(0, 0, &map, crate::vm::DispatchMode::Table, &[], &crate::vm::BlockMapPlan::default(), &[], &[]);
        let ha = add_handler_offset(&a, &map);
        let hb = add_handler_offset(&b, &map);
        assert_eq!(&a[ha..ha + 48], &b[hb..hb + 48]);
    }
}
