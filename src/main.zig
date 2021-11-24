const std = @import("std");
const Cpu = @import("Cpu.zig");

const C = @import("utility.zig").Colour;
const hexdump = @import("utility.zig").hexdump;

// const input_file = @embedFile("../gba_bios.bin");
const input_file = @embedFile("../tonc/first.gba");
// const input_file = @embedFile("../template.gba");

pub fn main() anyerror!void {
    // --- run from external ram ---
    // var cpu = Cpu{};
    // std.mem.copy(u8, &cpu.external_work_ram, input_file);

    // jump to external RAM
    // cpu.reg[15] = 0x200_0000;
    // -----------------------------

    // --- run from gamepak rom ---
    var cpu = Cpu{ .game_pak = input_file };
    // jump to game pak rom
    cpu.reg[15] = 0x800_0000;
    // hexdump(cpu.game_pak, 0x842B, .{
    //     .offset = 0x800_0000,
    //     .highlight = .{ .start = 0x842C, .end = 0x8438 },
    // });

    var prog_counter: usize = 0;
    while (true) : (prog_counter += 1) {
        var instr: u32 = cpu.getNextInstruction() catch break;
        cpu.dumpRegisters();

        const should_run = cpu.checkCondition(instr);
        {
            if (!should_run) std.debug.print(C.Dim, .{});
            std.debug.print(
                "{X:0>8}  {X:0>8}\n          ",
                .{ cpu.reg[15], instr },
            );
            // std.debug.print("  {b:0>32}\n", .{instr});

            if (should_run) std.debug.print(C.BrightCyan, .{});
            std.debug.print("{}" ++ C.Reset ++ "\n", .{cpu.decode(instr)});
        }
        if (!should_run) {
            cpu.reg[15] += 4;
            continue;
        }

        switch (cpu.decode(instr)) {
            .Branch => cpu.branch(instr),
            .BranchExchange => cpu.branchExchange(instr),
            .SingleDataTransfer => cpu.singleDataTransfer(instr) catch break,
            .BlockDataTransfer => cpu.blockDataTransfer(instr),
            .DataProcessing => cpu.dataProcessing(instr),
            else => cpu.incrementProgramCounter(),
        }
        _ = prog_counter;
    }
}
