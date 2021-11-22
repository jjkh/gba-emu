const std = @import("std");
const Cpu = @import("Cpu.zig");

// const input_file = @embedFile("../gba_bios.bin");
const input_file = @embedFile("../tonc/first.gba");
// const input_file = @embedFile("../template.gba");

pub fn main() anyerror!void {
    var cpu = Cpu{ .game_pak = input_file[0..input_file.len] };
    std.log.info("{}", .{input_file.len});

    // jump to game pak rom
    cpu.reg[15] = 0x800_0000;

    var prog_counter: usize = 0;
    while (true) : (prog_counter += 1) {
        var instr: u32 = cpu.getNextInstruction();
        cpu.dumpRegisters();
        std.debug.print("[{: >4}] {X:0>8}: {X:0>8} {} ({})\n", .{
            prog_counter,
            cpu.reg[15],
            instr,
            Cpu.checkCondition(instr),
            Cpu.decode(instr),
        });
        std.debug.print("  {b:0>32}\n", .{instr});

        switch (Cpu.decode(instr)) {
            .Branch => cpu.branch(instr),
            .BlockDataTransfer => cpu.blockDataTransfer(instr),
            .DataProcessing => cpu.dataProcessing(instr),
            else => cpu.reg[15] += 4,
        }
    }
}
