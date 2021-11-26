trace: bool = false,

buf_writer: BufferedWriter(4096, std.fs.File.Writer),
counting_writer: CountingWriter(@TypeOf(std.io.null_writer)) = std.io.countingWriter(std.io.null_writer),
indent_level: u8 = 0,
box_width: ?u16 = null,
continuing_line: bool = false,

const std = @import("std");
const BufferedWriter = std.io.BufferedWriter;
const CountingWriter = std.io.CountingWriter;

const Log = @This();

pub const TextFormat = struct {
    pub const YellowBg = "\x1b[30;43m";
    pub const RedBg = "\x1b[1;41m";
    pub const BlueBg = "\x1b[44m";
    pub const CyanBg = "\x1b[30;46m";

    pub const BrightCyan = "\x1b[1;96m";
    pub const Yellow = "\x1b[1;93m";
    pub const Red = "\x1b[31m";

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
    pub const ItalicReset = "\x1b[23m";
};

pub fn init() Log {
    return .{ .buf_writer = std.io.bufferedWriter(std.io.getStdOut().writer()) };
}

const LogOptions = struct {
    text_format: ?[]const u8 = null,
    newline: bool = true,
    ignore_indent: bool = false,
};

fn count_and_print(self: *Log, comptime format: []const u8, args: anytype) !void {
    try self.buf_writer.writer().print(format, args);
    try self.counting_writer.writer().print(format, args);
}

pub fn print(self: *Log, comptime format: []const u8, args: anytype, opts: LogOptions) void {
    if (!self.trace) return;
    const buf_writer = self.buf_writer.writer();

    if (!self.continuing_line) {
        if (self.box_width != null)
            _ = buf_writer.write("| ") catch unreachable
        else if (!opts.ignore_indent)
            buf_writer.writeByteNTimes(' ', self.indent_level * 4) catch unreachable;
    }

    if (opts.text_format) |tf|
        _ = buf_writer.write(tf) catch unreachable;

    self.count_and_print(format, args) catch unreachable;

    if (opts.text_format) |_|
        _ = buf_writer.write(TextFormat.Reset) catch unreachable;

    if (opts.newline) {
        self.continuing_line = false;

        self.boxEndLine();
        buf_writer.writeByte('\n') catch unreachable;
    } else {
        self.continuing_line = true;
    }
}

pub fn startBox(self: *Log, width: u16, title: ?[]const u8) void {
    if (!self.trace) return;
    if (self.box_width != null) self.stopBox();
    const buf_writer = self.buf_writer.writer();

    if (self.continuing_line) {
        buf_writer.writeByte('\n') catch unreachable;
    }

    const title_len = if (title) |t| t.len + 2 else 0;
    if (width < title_len + 6) unreachable;

    _ = buf_writer.write("+--") catch unreachable;
    if (title) |t| {
        buf_writer.writeByte(' ') catch unreachable;
        self.print("{s}", .{t}, .{ .text_format = TextFormat.Italic, .newline = false });
        buf_writer.writeByte(' ') catch unreachable;
    }
    buf_writer.writeByteNTimes('-', width - title_len) catch unreachable;
    _ = buf_writer.write("+\n") catch unreachable;

    self.box_width = width;
    self.counting_writer.bytes_written = 0;
    self.continuing_line = false;
}

pub fn stopBox(self: *Log) void {
    if (!self.trace) return;

    if (self.box_width == null) return;
    const buf_writer = self.buf_writer.writer();

    if (self.continuing_line) {
        self.boxEndLine();
        buf_writer.writeByte('\n') catch unreachable;
    }

    buf_writer.writeByte('+') catch unreachable;
    buf_writer.writeByteNTimes('-', self.box_width.? + 2) catch unreachable;
    _ = buf_writer.write("+\n") catch unreachable;

    self.box_width = null;
}

fn boxEndLine(self: *Log) void {
    if (self.box_width == null) return;

    if (self.counting_writer.bytes_written > self.box_width.?)
        self.box_width = @intCast(u16, self.counting_writer.bytes_written);

    const buf_writer = self.buf_writer.writer();
    buf_writer.writeByteNTimes(' ', self.box_width.? - self.counting_writer.bytes_written) catch unreachable;
    _ = buf_writer.write(" |") catch unreachable;

    self.counting_writer.bytes_written = 0;
}

pub fn flush(self: *Log) void {
    self.buf_writer.flush() catch unreachable;
}

pub fn indent(self: *Log) void {
    self.indent_level += 1;
}

pub fn deindent(self: *Log) void {
    if (self.indent_level == 0) return;

    self.indent_level -= 1;
}

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

pub fn hexdump(self: *Log, buf: []const u8, target: usize, opt: HexdumpOptions) void {
    if (!self.trace) return;

    const t = @intCast(i32, std.math.clamp(target, 0, buf.len));
    const line_start = t - @mod(t, opt.line_length);

    const dump_start = @intCast(usize, std.math.max(0, line_start - opt.line_length * opt.context));
    const dump_end = @intCast(usize, std.math.min(buf.len, line_start + opt.line_length * (opt.context + 1)));

    // highlight defaults to the target byte unless specified
    const highlight_start = if (opt.highlight) |h| h.start else target;
    const highlight_end = if (opt.highlight) |h| h.end else target + 1;

    var index: usize = dump_start;
    while (index < dump_end) : (index += opt.line_length) {
        self.print("{X:0>8}  ", .{index + opt.offset}, .{ .text_format = TextFormat.Dim ++ TextFormat.Italic, .newline = false });

        if (index > highlight_start and index < highlight_end)
            self.print(TextFormat.BlueBg, .{}, .{ .newline = false });

        // hex view
        {
            var i: usize = index;

            while (i < index + opt.line_length) : (i += 1) {
                if (i == highlight_end)
                    self.print(TextFormat.Reset, .{}, .{ .newline = false });

                if (i % 2 == 0)
                    self.print(" ", .{}, .{ .newline = false });

                if (i == highlight_start)
                    self.print(TextFormat.BlueBg, .{}, .{ .newline = false });

                if (i >= dump_end)
                    self.print("  ", .{}, .{ .newline = false })
                else
                    self.print("{X:0>2}", .{buf[i]}, .{ .newline = false });
            }
        }

        self.print(TextFormat.Reset ++ "  |  ", .{}, .{ .newline = false });
        if (index > highlight_start and index < highlight_end)
            self.print(TextFormat.BlueBg, .{}, .{ .newline = false });

        // ascii view
        {
            var i: usize = index;
            while (i < index + opt.line_length) : (i += 1) {
                if (i == highlight_end)
                    self.print(TextFormat.Reset, .{}, .{ .newline = false })
                else if (i == highlight_start)
                    self.print(TextFormat.BlueBg, .{}, .{ .newline = false });

                if (i >= dump_end)
                    self.print(" ", .{}, .{ .newline = false })
                else if (std.ascii.isPrint(buf[i]))
                    self.print("{c}", .{buf[i]}, .{ .newline = false })
                else if (i >= highlight_start and i <= highlight_end)
                    self.print(".", .{}, .{ .newline = false })
                else
                    self.print(".", .{}, .{ .text_format = TextFormat.Dim, .newline = false });
            }
        }
        self.print(TextFormat.Reset, .{}, .{});
    }
}

pub fn waitForUserInput(self: *Log) void {
    self.print("<< Press ENTER to continue >>", .{}, .{ .text_format = TextFormat.Yellow, .ignore_indent = true });
    self.flush();

    var buf: [16]u8 = undefined;
    _ = std.io.getStdIn().reader().read(&buf) catch {};
}
