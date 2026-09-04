use std::collections::HashMap;

// VM register file: reg n at [rbp + n*8 - 0x80]  (r0..r15 → [rbp-0x80]..[rbp-0x08])
// Resolved API pointers: GPA [rbp-0xC0], GetStdHandle [rbp-0xB8], WriteFile [rbp-0xB0],
//   ExitProcess [rbp-0xA8], stdout [rbp-0xA0]
// Interpreter metadata (disp32 bytes are NOT the hex offset — e.g. [rbp-0xD0] = 30 FF FF FF):
//   call depth [rbp-0xD0], push idx [rbp-0xD8], cmp flags [rbp-0xE0],
//   native_call rsi [rbp-0xE8], call temp [rbp-0xF0]
// Return addrs: [rbp + depth*8 - 0x200]; VM push stack: [rbp + idx*8 - 0x280]
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
        self.emit(&[0x48, 0x81, 0xEC, 0x00, 0x03, 0x00, 0x00]);
        self.emit(&[0x48, 0x83, 0xE4, 0xF0]);
        // VM metadata below API block; disp32 bytes 30/28/20/18 = [rbp-0xD0..-0xE8]
        self.emit(&[0x48, 0xC7, 0x85, 0x30, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00]); // call depth
        self.emit(&[0x48, 0xC7, 0x85, 0x28, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00]); // push idx
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
        self.emit(&[0x48, 0x89, 0x85, 0x20, 0xFF, 0xFF, 0xFF]);
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
        self.emit(&[0x48, 0x89, 0xB5, 0x10, 0xFF, 0xFF, 0xFF]);
        self.lea_rip_rel32(0x48, 1, "bytecode");
        self.emit(&[0x48, 0x8B, 0xB5, 0x10, 0xFF, 0xFF, 0xFF]);
        self.emit(&[0x48, 0x29, 0xCE]);
        self.emit(&[0x48, 0x8B, 0x95, 0x30, 0xFF, 0xFF, 0xFF]);
        self.emit(&[0x48, 0x89, 0xB4, 0xD5, 0x00, 0xFE, 0xFF, 0xFF]);
        self.emit(&[0x48, 0xFF, 0xC2]);
        self.emit(&[0x48, 0x89, 0x95, 0x30, 0xFF, 0xFF, 0xFF]);
        self.lea_rip_rel32(0x48, 6, "bytecode");
        self.emit(&[0x48, 0x01, 0xF0]);
        self.emit(&[0x48, 0x89, 0xC6]);
        self.jmp_to_dispatch();

        self.label("h_ret");
        self.emit(&[0x48, 0x8B, 0x85, 0x30, 0xFF, 0xFF, 0xFF]);
        self.emit(&[0x48, 0xFF, 0xC8]);
        self.emit(&[0x48, 0x89, 0x85, 0x30, 0xFF, 0xFF, 0xFF]);
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
        self.emit(&[0x48, 0x8B, 0x95, 0x28, 0xFF, 0xFF, 0xFF]);
        self.emit(&[0x48, 0x89, 0x84, 0xD5, 0x80, 0xFD, 0xFF, 0xFF]);
        self.emit(&[0x48, 0xFF, 0xC2]);
        self.emit(&[0x48, 0x89, 0x95, 0x28, 0xFF, 0xFF, 0xFF]);
        self.jmp_to_dispatch();

        self.label("h_pop");
        self.emit(&[0x0F, 0xB6, 0x0E]);
        self.emit(&[0x48, 0xFF, 0xC6]);
        self.emit(&[0x48, 0x8B, 0x95, 0x28, 0xFF, 0xFF, 0xFF]);
        self.emit(&[0x48, 0xFF, 0xCA]);
        self.emit(&[0x48, 0x89, 0x95, 0x28, 0xFF, 0xFF, 0xFF]);
        self.emit(&[0x48, 0x8B, 0x84, 0xD5, 0x80, 0xFD, 0xFF, 0xFF]);
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
        self.emit(&[0xFF, 0xB5, 0x20, 0xFF, 0xFF, 0xFF]);
        self.emit(&[0x9D]);
        self.jcc_rel32(jcc, "jmpif_taken");
        self.jmp_rel32("jmpif_not_taken");
    }

    fn emit_native_call_handler(&mut self) {
        self.emit(&[0x48, 0x8B, 0x06]);
        self.emit(&[0x48, 0x83, 0xC6, 0x08]);
        // Save bytecode pointer past func id at [rbp-0xE8] (18 FF FF FF).
        self.emit(&[0x48, 0x89, 0xB5, 0x18, 0xFF, 0xFF, 0xFF]);

        // IAT win64 ABI path when func_id >= 0x100000000
        self.emit(&[0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]); // mov rcx, 0x100000000
        self.emit(&[0x48, 0x39, 0xC8]); // cmp rax, rcx
        self.jcc_rel32(0x83, "nc_iat"); // jae nc_iat

        self.emit(&[0x48, 0x83, 0xF8, 0x01]);
        self.jcc_rel32(0x84, "nc_func1");
        self.emit(&[0x48, 0x83, 0xF8, 0x03]);
        self.jcc_rel32(0x84, "nc_func3");

        self.label("nc_func2");
        self.emit(&[0x48, 0x8B, 0x45, 0x90]);
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
        self.emit(&[0x41, 0x89, 0xDB]); // mov ebx, r11d
        self.emit(&[0x81, 0xE3, 0xFF, 0xFF, 0xFF, 0x7F]); // and ebx, 0x7fffffff
        self.emit(&[0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00]); // PEB
        self.emit(&[0x48, 0x8B, 0x40, 0x10]); // ImageBase
        self.emit(&[0x48, 0x01, 0xD8]); // add rax, rbx -> &IAT slot
        self.emit(&[0x48, 0x8B, 0x00]); // resolved import -> rax
        // win64 ABI: rcx, rdx, r8, r9 from VM r0..r3 (matches nc1/nc3 and 75ebd99 layout)
        self.emit(&[0x48, 0x8B, 0x8D, 0x80, 0xFF, 0xFF, 0xFF]); // rcx <- VM r0
        self.emit(&[0x48, 0x8B, 0x95, 0x78, 0xFF, 0xFF, 0xFF]); // rdx <- VM r1
        self.emit(&[0x4C, 0x8B, 0x85, 0x70, 0xFF, 0xFF, 0xFF]); // r8  <- VM r2
        self.emit(&[0x4C, 0x8B, 0x8D, 0x60, 0xFF, 0xFF, 0xFF]); // r9  <- VM r4 slot (75ebd99)
        self.emit(&[0x41, 0xF7, 0xC3, 0x00, 0x00, 0x00, 0x80]); // test r11d, 0x80000000
        self.jcc_rel32(0x84, "nc_iat_call"); // jz — putchar / integer arg, no ptr reloc
        self.lea_rip_rel32(0x4C, 2, "bytecode"); // lea r10, [rip+bytecode] (keep ebx free)
        self.emit(&[0x49, 0x01, 0xD1]); // add rcx, r10
        self.label("nc_iat_call");
        self.emit(&[0x48, 0x83, 0xEC, 0x28]);
        self.emit(&[0xFF, 0xD0]);
        self.emit(&[0x48, 0x83, 0xC4, 0x28]);
        self.jmp_rel32("nc_done");

        self.label("nc_done");
        self.emit(&[0x48, 0x8B, 0xB5, 0x18, 0xFF, 0xFF, 0xFF]);
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
        let handlers: [(u8, &str); 16] = [
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
    fn vm_metadata_slots_do_not_alias_vm_registers() {
        let (stub, _) = create_vm_interpreter_stub(0, 0);
        // [rbp-0xD0] = disp bytes 30 FF FF FF; must not use A8/B0 (those alias r5/r6 API slots).
        let call_depth_init = [0x48u8, 0xC7, 0x85, 0x30, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00];
        let push_idx_init = [0x48u8, 0xC7, 0x85, 0x28, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00];
        assert!(
            stub.windows(call_depth_init.len()).any(|w| w == call_depth_init),
            "call depth must use [rbp-0xD0] (30 FF FF FF), not [rbp-0x58]"
        );
        assert!(
            stub.windows(push_idx_init.len()).any(|w| w == push_idx_init),
            "push stack index must use [rbp-0xD8] (28 FF FF FF), not [rbp-0x50]"
        );
        let flags_store = [0x48u8, 0x89, 0x85, 0x20, 0xFF, 0xFF, 0xFF];
        assert!(
            stub.windows(flags_store.len()).any(|w| w == flags_store),
            "cmp flags must use [rbp-0xE0] (20 FF FF FF), not VM r2 at [rbp-0x70]"
        );
        let rsi_save = [0x48u8, 0x89, 0xB5, 0x18, 0xFF, 0xFF, 0xFF];
        assert!(
            stub.windows(rsi_save.len()).any(|w| w == rsi_save),
            "native_call resume must use [rbp-0xE8] (18 FF FF FF)"
        );
        let wrong_depth = [0x48u8, 0xC7, 0x85, 0xA8, 0xFF, 0xFF, 0xFF];
        assert!(
            !stub.windows(wrong_depth.len()).any(|w| w == wrong_depth),
            "must not init call depth at [rbp-0x58] (A8 FF FF FF)"
        );
    }

    #[test]
    fn iat_native_call_maps_x64_rcx_from_vm_reg0() {
        let (stub, _) = create_vm_interpreter_stub(0, 0);
        // nc_iat must load win64 rcx from VM r0 slot [rbp-0x80] (string/char arg)
        let rcx_from_r0 = [0x48u8, 0x8B, 0x8D, 0x80, 0xFF, 0xFF, 0xFF];
        assert!(
            stub.windows(rcx_from_r0.len()).any(|w| w == rcx_from_r0),
            "IAT path must map x64 rcx from VM register 0"
        );
        let rdx_from_r1 = [0x48u8, 0x8B, 0x95, 0x78, 0xFF, 0xFF, 0xFF];
        assert!(
            stub.windows(rdx_from_r1.len()).any(|w| w == rdx_from_r1),
            "IAT path must map x64 rdx from VM register 1"
        );
        let ptr_fixup = [0x49u8, 0x01, 0xD1]; // add rcx, r10 after lea r10, [bytecode]
        assert!(
            stub.windows(ptr_fixup.len()).any(|w| w == ptr_fixup),
            "IAT ptr path must add bytecode base to rcx via r10"
        );
        let rcx_from_r1 = [0x48u8, 0x8B, 0x8D, 0x78, 0xFF, 0xFF, 0xFF];
        assert!(
            !stub.windows(rcx_from_r1.len()).any(|w| w == rcx_from_r1),
            "IAT path must not load rcx from VM r1 (breaks putchar in r0)"
        );
    }
}
