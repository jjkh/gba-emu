const std = @import("std");

pub const Colour = struct {
    pub const Reset = "\x1b[0m";
    pub const Bold = "\x1b[1m";
    pub const Dim = "\x1b[2m";
    pub const Italic = "\x1b[3m";
    pub const Underline = "\x1b[4m";
    pub const Blinking = "\x1b[5m";
    pub const Inverse = "\x1b[7m";
    pub const Hidden = "\x1b[8m";
    pub const Strikethrough = "\x1b[9m";

    pub const DimReset = "\x1b[22m";
};

const HexdumpOptions = struct {
    // byte length of each line of the hexdump
    line_length: u16 = 32,
    // lines before and after the target to print
    context: u16 = 4,
    // offset for displayed addresses
    offset: usize = 0,
    // optional region of bytes to highlight
    highlight: ?struct {
        // inclusive
        start: usize = 0,
        // exclusive
        end: usize = 0,
    } = null,
};

pub fn hexdump(buf: []const u8, target: usize, opt: HexdumpOptions) void {
    const t = @intCast(i32, std.math.clamp(target, 0, buf.len));
    const line_start = t - @mod(t, opt.line_length);

    const dump_start = @intCast(usize, std.math.max(0, line_start - opt.line_length * opt.context));
    const dump_end = @intCast(usize, std.math.min(buf.len, line_start + opt.line_length * (opt.context + 1)));

    // highlight defaults to the target byte unless specified
    const highlight_start = if (opt.highlight) |h| h.start else target;
    const highlight_end = if (opt.highlight) |h| h.end else target + 1;

    var index: usize = dump_start;
    while (index < dump_end) : (index += opt.line_length) {
        std.debug.print(Colour.Dim ++ Colour.Italic ++ "{X:0>8}  " ++ Colour.Reset, .{index + opt.offset});

        if (index > highlight_start and index < highlight_end)
            std.debug.print(Colour.Inverse, .{});

        // hex view
        {
            var i: usize = index;

            while (i < index + opt.line_length) : (i += 1) {
                if (i == highlight_end)
                    std.debug.print(Colour.Reset, .{});

                if (i % 2 == 0)
                    std.debug.print(" ", .{});

                if (i == highlight_start)
                    std.debug.print(Colour.Inverse, .{});

                if (i >= dump_end)
                    std.debug.print("  ", .{})
                else
                    std.debug.print("{X:0>2}", .{buf[i]});
            }
        }

        std.debug.print(Colour.Reset ++ "  |  ", .{});
        if (index > highlight_start and index < highlight_end)
            std.debug.print(Colour.Inverse, .{});

        // ascii view
        {
            var i: usize = index;
            while (i < index + opt.line_length) : (i += 1) {
                if (i == highlight_end)
                    std.debug.print(Colour.Reset, .{})
                else if (i == highlight_start)
                    std.debug.print(Colour.Inverse, .{});

                if (i >= dump_end)
                    std.debug.print(" ", .{})
                else if (std.ascii.isPrint(buf[i]))
                    std.debug.print("{c}", .{buf[i]})
                else if (i >= highlight_start and i <= highlight_end)
                    std.debug.print(".", .{})
                else
                    std.debug.print(Colour.Dim ++ "." ++ Colour.DimReset, .{});
            }
        }
        std.debug.print(Colour.Reset ++ "\n", .{});
    }
}