const std = @import("std");
const Cpu = @import("Cpu.zig");

const Log = @import("Log.zig");

// const input_file = @embedFile("../gba_bios.bin");
const input_file = @embedFile("../tonc/first.gba");
// const input_file = @embedFile("../template.gba");

pub fn main() anyerror!void {
    var log = Log.init();
    defer log.flush();
    // log.trace = true;

    // --- run from external ram ---
    // var cpu = Cpu{};
    // std.mem.copy(u8, &cpu.external_work_ram, input_file);

    // jump to external RAM
    // cpu.reg[15] = 0x200_0000;
    // -----------------------------

    // --- run from gamepak rom ---
    var cpu = Cpu{ .log = &log, .game_pak = input_file };
    // jump to game pak rom
    cpu.reg[15] = 0x800_0000;
    log.hexdump(cpu.game_pak, 0x106, .{
        .line_length = 16,
        .context = 10,
        .offset = 0x800_0000,
        .highlight = .{ .start = 0x164, .end = 0x166 },
    });

    var prog_counter: usize = 0;
    while (true) : (prog_counter += 1) {
        if (cpu.reg[15] >= 0x08000196) {
            log.trace = true;
        }

        const instr = cpu.getNextInstruction() catch break;
        const instr_type = cpu.decode(instr);
        cpu.dumpRegisters();
        log.flush();
        const should_run = cpu.shouldExecuteInstruction(instr);

        log.print("{X:0>8}  {X:0>8}", .{ cpu.reg[15], instr }, .{});
        log.indent();
        defer log.deindent();

        // if (instr_type.isThumb())
        //     log.print("{b:0>16}", .{instr}, .{})
        // else
        //     log.print("{b:0>32}", .{instr}, .{});
        // log.indent();
        // defer log.deindent();
        log.print("{}", .{instr_type}, .{});

        if (!should_run) {
            cpu.reg[15] += 4;
            continue;
        }

        switch (instr_type) {
            .Branch => cpu.branch(instr),
            .BranchExchange => cpu.branchExchange(instr),
            .SingleDataTransfer => cpu.singleDataTransfer(instr) catch break,
            .BlockDataTransfer => cpu.blockDataTransfer(instr),
            .DataProcessing => cpu.dataProcessing(instr),
            .ThumbBranchUnconditional => cpu.thumbBranchUnconditional(@truncate(u16, instr)),
            .ThumbBranchConditional => cpu.thumbBranchConditional(@truncate(u16, instr)),
            .ThumbBranchLongWithLink => cpu.thumbBranchLongWithLink(instr),
            .ThumbHiRegOperationsBranchExchange => cpu.thumbHiRegOperationsBranchExchange(@truncate(u16, instr)),
            .ThumbPcRelativeLoad => cpu.thumbPcRelativeLoad(@truncate(u16, instr)),
            .ThumbMoveShifted => cpu.thumbMoveShifted(@truncate(u16, instr)),
            .ThumbAluImmediate => cpu.thumbAluImmediate(@truncate(u16, instr)),
            .ThumbAluReg => cpu.thumbAluReg(@truncate(u16, instr)),
            .ThumbAddSub => cpu.thumbAddSub(@truncate(u16, instr)),
            .ThumbLoadStoreMultiple => cpu.thumbLoadStoreMultiple(@truncate(u16, instr)),
            else => {
                if (instr_type.isThumb())
                    cpu.reg[15] += 2
                else
                    cpu.reg[15] += 4;
            },
        }

        if (log.trace)
            log.waitForUserInput();

        _ = prog_counter;
    }

    log.print("\nExecution finished @0x{X:0>8} (crash?)", .{cpu.reg[15]}, .{ .text_format = Log.TextFormat.RedBg });
    log.hexdump(cpu.game_pak, cpu.reg[15], .{ .offset = 0x800_0000, .line_length = 16 });
}
