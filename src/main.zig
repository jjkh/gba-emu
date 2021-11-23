const std = @import("std");
const Cpu = @import("Cpu.zig");

const C = @import("utility.zig").Colour;
const hexdump = @import("utility.zig").hexdump;

// const input_file = @embedFile("../gba_bios.bin");
const input_file = @embedFile("../tonc/first.gba");
// const input_file = @embedFile("../template.gba");

pub fn main() anyerror!void {
    var cpu = Cpu{ .game_pak = input_file[0..input_file.len] };

    // jump to game pak rom
    cpu.reg[15] = 0x800_0000;
    // hexdump(cpu.game_pak, 0x842B, .{
    //     .offset = 0x800_0000,
    //     .highlight = .{ .start = 0x842C, .end = 0x8438 },
    // });

    var prog_counter: usize = 0;
    while (true) : (prog_counter += 1) {
        var instr: u32 = cpu.getNextInstruction() catch return;
        // cpu.dumpRegisters();

        const should_run = cpu.checkCondition(instr);
        {
            if (!should_run) std.debug.print(C.Dim, .{});
            std.debug.print("[{: >4}] {X:0>8} {X:0>8}\n       ", .{ prog_counter, cpu.reg[15], instr });
            // std.debug.print("  {b:0>32}\n", .{instr});

            if (should_run) std.debug.print(C.Inverse, .{});
            std.debug.print("{}\n", .{Cpu.decode(instr)});

            std.debug.print(C.Reset, .{});
        }
        if (!should_run) {
            cpu.reg[15] += 4;
            continue;
        }

        switch (Cpu.decode(instr)) {
            .Branch => cpu.branch(instr),
            .BlockDataTransfer => cpu.blockDataTransfer(instr),
            .DataProcessing => cpu.dataProcessing(instr),
            else => cpu.reg[15] += 4,
        }
    }
}
