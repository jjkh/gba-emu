const std = @import("std");
const SDL = @import("sdl2");

const Cpu = @import("Cpu.zig");
const Log = @import("Log.zig");

// const input_file = @embedFile("../gba_bios.bin");
// const input_file = @embedFile("../tonc/first.gba");
const input_file = @embedFile("../tonc/m3_demo.gba");
// const input_file = @embedFile("../template.gba");

pub fn main() !void {
    var log = Log.init();
    defer log.flush();
    // log.trace = true;

    try SDL.init(.{
        .video = true,
        .events = true,
    });
    defer SDL.quit();

    var window = try SDL.createWindow(
        "GBA Emulator",
        .{ .centered = {} },
        .{ .centered = {} },
        960,
        640,
        .{
            .shown = true,
            .allow_high_dpi = true,
        },
    );
    defer window.destroy();

    var renderer = try SDL.createRenderer(window, null, .{ .accelerated = true });
    defer renderer.destroy();

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
    // log.hexdump(cpu.game_pak, 0x106, .{
    //     .line_length = 16,
    //     .context = 10,
    //     .offset = 0x800_0000,
    //     .highlight = .{ .start = 0x164, .end = 0x166 },
    // });

    var wait_for_input: bool = false;

    var prog_timer = std.time.Timer.start() catch unreachable;
    var prog_counter: usize = 0;
    while (true) : (prog_counter += 1) {
        // if (cpu.reg[15] == 0x08000422) {
        //     log.trace = true;
        //     wait_for_input = true;
        // }

        const instr = cpu.getNextInstruction() catch break;
        const instr_type = cpu.decode(instr);
        cpu.dumpRegisters();
        const should_run = cpu.shouldExecuteInstruction(instr);

        log.print("{X:0>8}  {X:0>8}", .{ cpu.reg[15], instr }, .{});
        log.indent();
        defer log.deindent();

        // if (instr_type.isThumb() and instr_type != .ThumbBranchLongWithLink)
        //     log.print("{b:0>16}", .{@truncate(u16, instr)}, .{})
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
            .ThumbLoadStoreImmediateOffset => cpu.thumbLoadStoreImmediateOffset(@truncate(u16, instr)),
            .ThumbLoadStoreHalfword => cpu.thumbLoadStoreHalfword(@truncate(u16, instr)),
            .ThumbPushPopReg => cpu.thumbPushPopReg(@truncate(u16, instr)),
            .ThumbAddOffsetToStackPtr => cpu.thumbAddOffsetToStackPtr(@truncate(u16, instr)),
            .ThumbStackPtrRelativeLoadStore => cpu.thumbStackPtrRelativeLoadStore(@truncate(u16, instr)),
            .ThumbLoadStoreSignExt => cpu.thumbLoadStoreSignExt(@truncate(u16, instr)),
            else => {
                wait_for_input = true;

                if (instr_type.isThumb())
                    cpu.reg[15] += 2
                else
                    cpu.reg[15] += 4;
            },
        }

        if (log.trace)
            wait_for_input = true;

        {
            const old_title: ?[*c]const u8 = if (wait_for_input) SDL.c.SDL_GetWindowTitle(window.ptr) else null;
            if (wait_for_input) {
                log.trace = true;
                log.waitForUserInput();
                SDL.c.SDL_SetWindowTitle(window.ptr, "GBA Emulator (paused)");
            }
            defer if (old_title) |title|
                SDL.c.SDL_SetWindowTitle(window.ptr, title);

            while (true) {
                while (SDL.pollEvent()) |ev| {
                    switch (ev) {
                        .quit => return,
                        .key_down => |key| {
                            switch (key.scancode) {
                                .escape => return,
                                else => wait_for_input = false,
                            }
                        },
                        else => {},
                    }
                }
                if (!wait_for_input) {
                    break;
                }

                std.time.sleep(1000);
            }
        }

        // NOTE: only works for bg mode 3
        // if (prog_counter % 280_896 == 0) {
        if (prog_counter % 10_000 == 0) {
            try renderer.clear();

            var y: u32 = 0;
            while (y < 160) : (y += 1) {
                var x: u32 = 0;
                while (x < 240) : (x += 1) {
                    const Pixel = packed struct {
                        r: u5,
                        g: u5,
                        b: u5,
                        _: u1,
                    };
                    const px = @bitCast(Pixel, cpu.vram[y * 480 + x * 2] | @as(u16, cpu.vram[y * 480 + x * 2 + 1]) << 8);

                    try renderer.setColorRGB(@as(u8, px.r) << 3, @as(u8, px.g) << 3, @as(u8, px.b) << 3);
                    try renderer.fillRect(SDL.Rectangle{
                        .x = @intCast(c_int, x) * 4,
                        .y = @intCast(c_int, y) * 4,
                        .width = 4,
                        .height = 4,
                    });
                }
            }
            renderer.present();

            const time_in_ms = @intToFloat(f32, prog_timer.lap()) / 100_0000;
            var buf: [256]u8 = undefined;
            const title = try std.fmt.bufPrintZ(&buf, "GBA Emulator: {d:.2}ms ({d:.1} fps)", .{ time_in_ms, 1000 / time_in_ms });
            SDL.c.SDL_SetWindowTitle(window.ptr, title);
        }
    }
    log.trace = true;
    log.print("\nExecution finished @0x{X:0>8} (crash?)", .{cpu.reg[15]}, .{ .text_format = Log.TextFormat.RedBg });
    log.indent();
    defer log.deindent();
    cpu.dumpRegisters();
    log.hexdump(cpu.game_pak, cpu.reg[15], .{ .offset = 0x800_0000, .line_length = 16 });
}
