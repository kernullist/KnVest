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
//   push depth     [rbp-0xE8]  bytes 18 FF FF FF
//   char buf       [rbp-0xF0]  bytes 10 FF FF FF  (nc2/nc3 digit buffer; do not clobber)
//   ret addrs      [rbp + depth*8 - 0x200]
//   data stack     [rbp + idx*8 - 0x380]  (idx 16 must stay below ret[0] at -0x200; fits 0x400 frame)
pub fn create_vm_interpreter_stub(_image_base: u64, _section_rva: u32) -> (Vec<u8>, usize) {
    let mut e = StubEmitter::new();
    e.emit_prologue_and_api_resolve();
    e.emit_dispatch_loop();
    e.emit_handler_table_placeholder();
    e.emit_handlers();
    e.emit_strings_and_marker();
    e.finalize()
}

struct StubEmitter {
    code: Vec<u8>,
    labels: HashMap<&'static str, usize>,
    rel32: Vec<(usize, &'static str)>,
    lea_rip: Vec<(usize, &'static str)>,
    handler_table_start: Option<usize>,
}

impl StubEmitter {
    fn new() -> Self {
        Self {
            code: Vec::new(),
            labels: HashMap::new(),
            rel32: Vec::new(),
            lea_rip: Vec::new(),
            handler_table_start: None,
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
        self.emit(&[rex, 0x8D, 0x05 | (modrm_reg << 3), 0, 0, 0, 0]);
        self.lea_rip.push((self.pos() - 4, target));
    }

    fn jmp_to_dispatch(&mut self) {
        self.jmp_rel32("dispatch");
    }

    fn emit_prologue_and_api_resolve(&mut self) {
        self.emit(&[0x55]);
        self.emit(&[0x48, 0x89, 0xE5]);
        self.emit(&[0x48, 0x81, 0xEC, 0x00, 0x04, 0x00, 0x00]);
        self.emit(&[0x48, 0x83, 0xE4, 0xF0]);
        // Zero L2 call depth [rbp-0xC8] and push depth [rbp-0xE8]
        self.emit(&[0x48, 0xC7, 0x85, 0x38, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00]);
        self.emit(&[0x48, 0xC7, 0x85, 0x18, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00]);
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

        self.lea_rip_rel32(0x48, 6, "bytecode");
        self.emit(&[0x48, 0x89, 0xF6]);
        self.jmp_rel32("dispatch");

        self.label("module_fail");
        self.emit(&[0xCC]);
    }

    fn emit_dispatch_loop(&mut self) {
        self.label("dispatch");
        self.emit(&[0x0F, 0xB6, 0x06]);
        self.emit(&[0x48, 0xFF, 0xC6]);
        self.emit(&[0x3C, 0xFF]);
        self.jcc_rel32(0x84, "h_exit");
        self.emit(&[0x48, 0x8D, 0x1D, 0, 0, 0, 0]);
        self.lea_rip.push((self.pos() - 4, "handler_table"));
        self.emit(&[0x48, 0x63, 0x04, 0x83]);
        self.emit(&[0x48, 0x01, 0xD8]);
        self.emit(&[0xFF, 0xE0]);
    }

    fn emit_handlers(&mut self) {
        self.label("h_nop");
        self.jmp_to_dispatch();

        self.label("h_load_imm");
        self.emit(&[0x0F, 0xB6, 0x0E]);
        self.emit(&[0x48, 0xFF, 0xC6]);
        self.emit(&[0x48, 0x8B, 0x06]);
        self.emit(&[0x48, 0x83, 0xC6, 0x08]);
        self.emit(&[0x48, 0x89, 0x44, 0xCD, 0x80]);
        self.jmp_to_dispatch();

        self.label("h_move");
        self.emit(&[0x0F, 0xB6, 0x0E]);
        self.emit(&[0x48, 0xFF, 0xC6]);
        self.emit(&[0x0F, 0xB6, 0x3E]);
        self.emit(&[0x48, 0xFF, 0xC6]);
        self.emit(&[0x48, 0x8B, 0x44, 0xFD, 0x80]);
        self.emit(&[0x48, 0x89, 0x44, 0xCD, 0x80]);
        self.jmp_to_dispatch();

        self.label("h_add");
        self.emit(&[0x0F, 0xB6, 0x0E]);
        self.emit(&[0x48, 0xFF, 0xC6]);
        self.emit(&[0x0F, 0xB6, 0x3E]);
        self.emit(&[0x48, 0xFF, 0xC6]);
        self.emit(&[0x0F, 0xB6, 0x16]);
        self.emit(&[0x48, 0xFF, 0xC6]);
        self.emit(&[0x48, 0x8B, 0x44, 0xFD, 0x80]);
        self.emit(&[0x48, 0x03, 0x44, 0xD5, 0x80]);
        self.emit(&[0x48, 0x89, 0x44, 0xCD, 0x80]);
        self.jmp_to_dispatch();

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

        self.label("h_cmp32");
        self.emit(&[0x0F, 0xB6, 0x0E]);
        self.emit(&[0x48, 0xFF, 0xC6]);
        self.emit(&[0x0F, 0xB6, 0x3E]);
        self.emit(&[0x48, 0xFF, 0xC6]);
        self.emit(&[0x8B, 0x44, 0x8D, 0x80]); // mov eax, dword [rbp+rcx*8-0x80]
        self.emit(&[0x3B, 0x44, 0xBD, 0x80]); // cmp eax, dword [rbp+rdi*8-0x80]
        self.emit(&[0x9C]);
        self.emit(&[0x58]);
        self.emit(&[0x48, 0x25, 0xC1, 0x08, 0x00, 0x00]);
        self.emit(&[0x48, 0x89, 0x85, 0x70, 0xFF, 0xFF, 0xFF]);
        self.jmp_to_dispatch();

        self.label("h_jmp");
        self.emit(&[0x48, 0x8B, 0x06]);
        self.emit(&[0x48, 0x83, 0xC6, 0x08]);
        self.lea_rip_rel32(0x48, 6, "bytecode");
        self.emit(&[0x48, 0x01, 0xF0]);
        self.emit(&[0x48, 0x89, 0xC6]);
        self.jmp_to_dispatch();

        self.label("h_jmpif");
        self.emit_jmpif_handler();
        self.jmp_to_dispatch();

        self.label("h_call");
        self.emit(&[0x48, 0x8B, 0x06]);
        self.emit(&[0x48, 0x83, 0xC6, 0x08]);
        self.emit(&[0x48, 0x89, 0xB5, 0x68, 0xFF, 0xFF, 0xFF]);
        self.lea_rip_rel32(0x48, 1, "bytecode");
        self.emit(&[0x48, 0x8B, 0xB5, 0x68, 0xFF, 0xFF, 0xFF]);
        self.emit(&[0x48, 0x29, 0xCE]);
        self.emit(&[0x48, 0x8B, 0x95, 0x38, 0xFF, 0xFF, 0xFF]);
        self.emit(&[0x48, 0x89, 0xB4, 0xD5, 0x00, 0xFE, 0xFF, 0xFF]);
        self.emit(&[0x48, 0xFF, 0xC2]);
        self.emit(&[0x48, 0x89, 0x95, 0x38, 0xFF, 0xFF, 0xFF]);
        self.lea_rip_rel32(0x48, 6, "bytecode");
        self.emit(&[0x48, 0x01, 0xF0]);
        self.emit(&[0x48, 0x89, 0xC6]);
        self.jmp_to_dispatch();

        self.label("h_ret");
        self.emit(&[0x48, 0x8B, 0x85, 0x38, 0xFF, 0xFF, 0xFF]);
        self.emit(&[0x48, 0xFF, 0xC8]);
        self.emit(&[0x48, 0x89, 0x85, 0x38, 0xFF, 0xFF, 0xFF]);
        self.emit(&[0x48, 0x8B, 0x84, 0xC5, 0x00, 0xFE, 0xFF, 0xFF]);
        self.lea_rip_rel32(0x48, 6, "bytecode");
        self.emit(&[0x48, 0x01, 0xF0]);
        self.emit(&[0x48, 0x89, 0xC6]);
        self.jmp_to_dispatch();

        self.label("h_native_call");
        self.emit_native_call_handler();
        self.jmp_to_dispatch();

        self.label("h_push");
        self.emit(&[0x0F, 0xB6, 0x0E]);
        self.emit(&[0x48, 0xFF, 0xC6]);
        self.emit(&[0x48, 0x8B, 0x44, 0xCD, 0x80]);
        self.emit(&[0x48, 0x8B, 0x95, 0x18, 0xFF, 0xFF, 0xFF]);
        self.emit(&[0x48, 0x89, 0x84, 0xD5, 0x80, 0xF6, 0xFF, 0xFF]);
        self.emit(&[0x48, 0xFF, 0xC2]);
        self.emit(&[0x48, 0x89, 0x95, 0x18, 0xFF, 0xFF, 0xFF]);
        self.jmp_to_dispatch();

        self.label("h_pop");
        self.emit(&[0x0F, 0xB6, 0x0E]);
        self.emit(&[0x48, 0xFF, 0xC6]);
        self.emit(&[0x48, 0x8B, 0x95, 0x18, 0xFF, 0xFF, 0xFF]);
        self.emit(&[0x48, 0xFF, 0xCA]);
        self.emit(&[0x48, 0x89, 0x95, 0x18, 0xFF, 0xFF, 0xFF]);
        self.emit(&[0x48, 0x8B, 0x84, 0xD5, 0x80, 0xF6, 0xFF, 0xFF]);
        self.emit(&[0x48, 0x89, 0x44, 0xCD, 0x80]);
        self.jmp_to_dispatch();

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
        // Preserve VM r10..r12 in win64 callee-saved hw regs (64-bit mov, not dword).
        self.emit(&[0x49, 0x8B, 0x65, 0xD0]); // mov r12, [rbp-0x30] VM r10
        self.emit(&[0x49, 0x8B, 0x6D, 0xD8]); // mov r13, [rbp-0x28] VM r11
        self.emit(&[0x49, 0x8B, 0x75, 0xE0]); // mov r14, [rbp-0x20] VM r12
        self.emit(&[0x48, 0x83, 0xEC, 0x28]);
        self.emit(&[0xFF, 0xD3]); // call rbx
        self.emit(&[0x48, 0x83, 0xC4, 0x28]);
        self.emit(&[0x4D, 0x89, 0x75, 0xE0]); // mov [rbp-0x20], r14
        self.emit(&[0x4D, 0x89, 0x6D, 0xD8]); // mov [rbp-0x28], r13
        self.emit(&[0x49, 0x89, 0x65, 0xD0]); // mov [rbp-0x30], r12
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

    fn fill_handler_table(&mut self) {
        let table_base = self
            .handler_table_start
            .expect("handler table placeholder missing");
        let handlers: [(u8, &str); 18] = [
            (0x00, "h_nop"),
            (0x01, "h_load_imm"),
            (0x04, "h_move"),
            (0x05, "h_add"),
            (0x06, "h_sub"),
            (0x07, "h_mul"),
            (0x09, "h_cmp"),
            (0x0A, "h_jmp"),
            (0x0B, "h_jmpif"),
            (0x0C, "h_call"),
            (0x0D, "h_ret"),
            (0x0E, "h_native_call"),
            (0x0F, "h_push"),
            (0x10, "h_pop"),
            (0x11, "h_load_byte"),
            (0x13, "h_cmp32"),
            (0x14, "h_and"),
            (0xFF, "h_exit"),
        ];
        let default_off = self.handler_offset("h_nop", table_base);
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
    }

    fn handler_offset(&self, label: &str, table_base: usize) -> i32 {
        let handler = *self.labels.get(label).unwrap_or(&table_base);
        (handler as i64 - table_base as i64) as i32
    }

    fn emit_strings_and_marker(&mut self) {
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
        self.emit(b"VMBC");
        self.label("bytecode");
    }

    fn finalize(mut self) -> (Vec<u8>, usize) {
        self.fill_handler_table();
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
        (self.code, size)
    }
}

#[cfg(test)]
mod tests {
    use super::create_vm_interpreter_stub;

    /// InLoadOrderModuleList walk must advance `rcx = [rcx]` once per iteration (at
    /// `module_next`), not again at `module_loop` entry — double-advance skips kernel32.
    #[test]
    fn peb_module_walk_single_advance_per_iteration() {
        let (stub, _) = create_vm_interpreter_stub(0, 0);
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
    fn iat_native_call_threshold_uses_full_mov_rcx_imm64() {
        let (stub, _) = create_vm_interpreter_stub(0, 0);
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
        let (stub, _) = create_vm_interpreter_stub(0, 0);
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
        let (stub, _) = create_vm_interpreter_stub(0, 0);
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
        let (stub, _) = create_vm_interpreter_stub(0, 0);
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
        let data_stack_disp = [0x80u8, 0xF6, 0xFF, 0xFF];
        assert!(
            stub.windows(data_stack_disp.len()).filter(|w| *w == data_stack_disp).count() >= 2,
            "h_push/h_pop data stack must use [rbp-0x380] (80 F6 FF FF)"
        );
        assert!(
            !stub.windows(4).any(|w| w == [0x80, 0xFB, 0xFF, 0xFF]),
            "data stack must not use [rbp-0x480] (out of frame)"
        );
        assert!(
            !stub.windows(4).any(|w| w == [0x80, 0xFD, 0xFF, 0xFF]),
            "data stack must not use old [rbp-0x280] base (aliases ret at idx 16)"
        );
        let prologue_alloc = [0x48u8, 0x81, 0xEC, 0x00, 0x04, 0x00, 0x00];
        assert!(
            stub.windows(prologue_alloc.len()).any(|w| w == prologue_alloc),
            "prologue must allocate >= 0x400 bytes for L2 frame including data stack"
        );
        let qword_cmp = [0x48u8, 0x8B, 0x44, 0xCD, 0x80, 0x48, 0x3B, 0x44, 0xFD, 0x80];
        assert!(
            stub.windows(qword_cmp.len()).any(|w| w == qword_cmp),
            "h_cmp must use 64-bit qword compare (fact/loop JG depend on this)"
        );
        let dword_cmp32 = [0x8Bu8, 0x44, 0x8D, 0x80, 0x3B, 0x44, 0xBD, 0x80];
        assert!(
            stub.windows(dword_cmp32.len()).any(|w| w == dword_cmp32),
            "h_cmp32 must use 32-bit dword compare for nested u32 cmpl"
        );
        let spill_to_r12 = [0x49u8, 0x8B, 0x65, 0xD0];
        assert!(
            stub.windows(spill_to_r12.len()).any(|w| w == spill_to_r12),
            "nc_iat_call must save VM r10 into callee-saved r12 (64-bit mov) before external call"
        );
        let restore_r12 = [0x49u8, 0x89, 0x65, 0xD0];
        assert!(
            stub.windows(restore_r12.len()).any(|w| w == restore_r12),
            "nc_iat_call must restore VM r10 from r12 after external call"
        );
    }
}
