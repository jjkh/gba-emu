const std = @import("std");
const Cpu = @import("Cpu.zig");

const TF = @import("utility.zig").TextFormat;
const hexdump = @import("utility.zig").hexdump;
const waitForUserInput = @import("utility.zig").waitForUserInput;

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
    hexdump(cpu.game_pak, 0x106, .{
        .line_length = 16,
        .context = 10,
        .offset = 0x800_0000,
        .highlight = .{ .start = 0x164, .end = 0x166 },
    });

    var prog_counter: usize = 0;
    while (true) : (prog_counter += 1) {
        // waitForUserInput();

        var instr: u32 = cpu.getNextInstruction() catch break;
        cpu.dumpRegisters();
        const is_thumb = cpu.cpsr.t;
        const should_run = cpu.checkCondition(instr);
        {
            if (!should_run) std.debug.print(TF.Dim, .{});
            std.debug.print(
                "{X:0>8}  {X:0>8}\n          ",
                .{ cpu.reg[15], instr },
            );
            if (is_thumb)
                std.debug.print("\r    {b:0>16}\n          ", .{instr})
            else
                std.debug.print("\r    {b:0>32}\n          ", .{instr});

            if (should_run) std.debug.print(TF.BrightCyan, .{});
            std.debug.print("{}" ++ TF.Reset ++ "\n", .{cpu.decode(instr)});
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
            .ThumbBranchUnconditional => cpu.thumbBranchUnconditional(@intCast(u16, instr)),
            .ThumbPcRelativeLoad => cpu.thumbPcRelativeLoad(@intCast(u16, instr)),
            .ThumbMoveShifted => cpu.thumbMoveShifted(@intCast(u16, instr)),
            // .ThumbBranchLongWithLink => cpu.thumbBranchLongWithLink(@intCast(u16, instr)),
            else => {
                waitForUserInput();
                if (is_thumb)
                    cpu.reg[15] += 2
                else
                    cpu.reg[15] += 4;
                // cpu.incrementProgramCounter();
            },
        }
        _ = prog_counter;
    }

    std.debug.print("\n-- WARNING: Execution finished (crash?) -------------------------------\n", .{});
    hexdump(cpu.game_pak, cpu.reg[15], .{ .offset = 0x800_0000, .line_length = 16 });
    std.debug.print("-----------------------------------------------------------------------\n", .{});
}
