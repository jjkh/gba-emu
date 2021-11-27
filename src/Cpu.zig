const Cpu = @This();

const std = @import("std");

const Log = @import("Log.zig");
const TF = Log.TextFormat;

// register indices
const SP = 13;
const LR = 14;
const PC = 15;

const InstructionType = enum {
    BranchExchange,
    Branch,
    DataProcessing,
    MoveFromStatus,
    MoveToStatus,
    MoveToFlags,
    Multiply,
    MultiplyLong,
    SingleDataTransfer,
    HalfwordDataTransferRegOffset,
    HalfwordDataTransferImmediateOffset,
    BlockDataTransfer,
    SingleDataSwap,
    SoftwareInterrupt,
    ThumbMoveShifted,
    ThumbAddSub,
    ThumbAluImmediate,
    ThumbAluReg,
    ThumbHiRegOperationsBranchExchange,
    ThumbPcRelativeLoad,
    ThumbLoadStoreWithRegOffset,
    ThumbLoadStoreSignExt,
    ThumbLoadStoreImmediateOffset,
    ThumbLoadStoreHalfword,
    ThumbStackPtrRelativeLoadStore,
    ThumbLoadAddr,
    ThumbAddOffsetToStackPtr,
    ThumbPushPopReg,
    ThumbLoadStoreMultiple,
    ThumbBranchConditional,
    ThumbSoftwareInterrupt,
    ThumbBranchUnconditional,
    ThumbBranchLongWithLink,
    Unknown,

    pub fn isThumb(instr: @This()) bool {
        return std.mem.startsWith(u8, @tagName(instr), "Thumb");
    }
};

// 3.8 The Program Status Registers
const ProgramStatusRegister = packed struct {
    mode: u5 = 0b10011,
    t: bool = false,
    f: bool = true,
    i: bool = true,
    _reserved: u20 = 0,
    v: bool = false,
    c: bool = false,
    z: bool = false,
    n: bool = false,
};

// 4.2 The Condition Field
// In ARM state, all instructions are conditionally executed according to the state of the
// CPSR condition codes and the instruction’s condition field. This field (bits 31:28)
// determines the circumstances under which an instruction is to be executed. If the state
// of the C, N, Z and V flags fulfils the conditions encoded by the field, the instruction is
// executed, otherwise it is ignored.
const Condition = enum(u4) {
    // EQ (Z set)
    Equal,
    // NE (Z clear)
    NotEqual,
    // CS (C set)
    UnsignedHigherOrSame,
    // CC (C clear)
    UnsignedLower,
    // MI (N set)
    Negative,
    // PL (N clear)
    PositiveOrZero,
    // VS (V set)
    Overflow,
    // VC (V clear)
    NoOverflow,
    // HI (C set and Z clear)
    UnsignedHigher,
    // LS (C clear or Z set)
    UnsignedLowerOrSame,
    // GE (N equals V)
    GreaterOrEqual,
    // LT (N not equal to V)
    LessThan,
    // GT (Z clear AND (N equals V))
    GreaterThan,
    // LE (Z set OR (N not equal to V))
    LessThanOrEqual,
    // AL (ignored)
    Always,
    _,
};

log: *Log,

// 3.7 Registers
// ARM7TDMI has a total of 37 registers - 31 general-purpose 32-bit registers and six
// status registers - but these cannot all be seen at once. The processor state and
// operating mode dictate which registers are available to the programmer.
reg: [16]u32 = std.mem.zeroes([16]u32),
// used to highlight register differences between runs
prev_reg: [16]u32 = std.mem.zeroes([16]u32),

// 3.7.1 The ARM state register set
// The ARM state register set contains 16 directly accessible registers: R0 to R15. All of
// these except R15 are general-purpose, and may be used to hold either data or
// address values. In addition to these, there is a seventeenth register used to store
// status information.

// 3.7.2 The THUMB state register set
// The THUMB state register set is a subset of the ARM state set. The programmer has
// direct access to eight general registers, R0-R7, as well as the Program Counter (PC),
// a stack pointer register (SP), a link register (LR), and the CPSR. There are banked
// Stack Pointers, Link Registers and Saved Process Status Registers (SPSRs) for each
// privileged mode.

// 3.7.3 The relationship between ARM and THUMB state registers
//   R0   -> R0       -+
//   R1   -> R1        |
//   R2   -> R2        |
//   R3   -> R3        | Lo registers
//   R4   -> R4        |
//   R5   -> R5        |
//   R6   -> R6        |
//   R7   -> R7       -+
//           R8       -+
//           R9        |
//           R10       |
//           R11       | Hi registers
//           R12       |
//   SP   -> R13 (SP)  |
//   LR   -> R14 (LR)  |
//   PC   -> R15 (PC) -+
//   CPSR -> CPSR
//   SPSR -> SPSR

// 3.8 The Program Status Registers
// The ARM7TDMI contains a Current Program Status Register (CPSR), plus five Saved
// Program Status Registers (SPSRs) for use by exception handlers. These registers
// - hold information about the most recently performed ALU operation
// - control the enabling and disabling of interrupts
// - set the processor operating mode
cpsr: ProgramStatusRegister = ProgramStatusRegister{},

spsr: [5]ProgramStatusRegister = undefined,

// Internal Memory
//   BIOS ROM     16 KBytes
//   Work RAM     288 KBytes (Fast 32K on-chip, plus Slow 256K on-board)
//   VRAM         96 KBytes
//   OAM          1 KByte (128 OBJs 3x16bit, 32 OBJ-Rotation/Scalings 4x16bit)
//   Palette RAM  1 KByte (256 BG colors, 256 OBJ colors)

// General Internal Memory
//   00000000-00003FFF   BIOS - System ROM         (16 KBytes)
//   00004000-01FFFFFF   Not used
//   02000000-0203FFFF   WRAM - On-board Work RAM  (256 KBytes) 2 Wait
//   02040000-02FFFFFF   Not used
//   03000000-03007FFF   WRAM - On-chip Work RAM   (32 KBytes)
//   03008000-03FFFFFF   Not used
//   04000000-040003FE   I/O Registers
//   04000400-04FFFFFF   Not used
// Internal Display Memory
//   05000000-050003FF   BG/OBJ Palette RAM        (1 Kbyte)
//   05000400-05FFFFFF   Not used
//   06000000-06017FFF   VRAM - Video RAM          (96 KBytes)
//   06018000-06FFFFFF   Not used
//   07000000-070003FF   OAM - OBJ Attributes      (1 Kbyte)
//   07000400-07FFFFFF   Not used
// External Memory (Game Pak)
//   08000000-09FFFFFF   Game Pak ROM/FlashROM (max 32MB) - Wait State 0
//   0A000000-0BFFFFFF   Game Pak ROM/FlashROM (max 32MB) - Wait State 1
//   0C000000-0DFFFFFF   Game Pak ROM/FlashROM (max 32MB) - Wait State 2
//   0E000000-0E00FFFF   Game Pak SRAM    (max 64 KBytes) - 8bit Bus width
//   0E010000-0FFFFFFF   Not used
// Unused Memory Area
//   10000000-FFFFFFFF   Not used (upper 4bits of address bus unused)

rom: [0x4000]u8 = std.mem.zeroes([0x4000]u8),
external_work_ram: [0x40000]u8 = std.mem.zeroes([0x40000]u8),
internal_work_ram: [0x8000]u8 = std.mem.zeroes([0x8000]u8),

vram: [0x18000]u8 = std.mem.zeroes([0x18000]u8),

game_pak: []const u8 = undefined,

fn readU32(mem: []const u8, offset: u32) !u32 {
    if (mem.len < offset + 2)
        return error.BadAddress;

    var result: u32 = mem[offset] | @as(u32, mem[offset + 1]) << 8;

    if (mem.len < offset + 4)
        return result;

    return result | @as(u32, mem[offset + 2]) << 16 | @as(u32, mem[offset + 3]) << 24;
}

fn getBufForAddress(self: Cpu, addr: u32) ?[]const u8 {
    return switch (addr >> 24) {
        0x00 => &self.rom,
        0x02 => &self.external_work_ram,
        0x03 => &self.internal_work_ram,
        0x06 => &self.vram,
        0x08 => self.game_pak,
        else => null,
    };
}

fn getMutableBufForAddress(self: *Cpu, addr: u32) ?[]u8 {
    return switch (addr >> 24) {
        0x02 => &self.external_work_ram,
        0x03 => &self.internal_work_ram,
        0x06 => &self.vram,
        else => null,
    };
}

pub fn read(self: *Cpu, addr: u32) !u32 {
    return switch (addr >> 24) {
        0x00, 0x02, 0x03, 0x06, 0x08 => try readU32(self.getBufForAddress(addr).?, addr & 0x00FF_FFFF),
        else => {
            self.log.print("unimplemented address: {X:0>8}", .{addr}, .{ .text_format = TF.RedBg });
            return error.UnimplementedAddress;
        },
    };
}

fn writeMmio(self: *Cpu, addr: u32, value: u16) void {
    switch (addr) {
        0x0400_0000 => self.lcdControl(value),
        else => self.log.print("IO 0x{X:0>8} not handled!", .{addr}, .{ .text_format = TF.RedBg }),
    }
}

pub fn writeHalfword(self: *Cpu, addr: u32, value: u16) void {
    switch (addr >> 24) {
        0x04 => self.writeMmio(addr, @truncate(u16, value)),
        else => self.write(addr, value),
    }
}

pub fn write(self: *Cpu, addr: u32, value: u32) void {
    const buf = switch (addr >> 24) {
        0x02, 0x03, 0x06 => self.getMutableBufForAddress(addr).?[addr & 0x00FF_FFFF ..],
        0x04 => {
            self.writeHalfword(addr, @truncate(u16, value));
            self.writeHalfword(addr + 2, @truncate(u16, value >> 16));
            return;
        },
        else => unreachable,
    };
    std.mem.copy(u8, buf, &std.mem.toBytes(value));
}

pub fn getNextInstruction(self: *Cpu) !u32 {
    return try self.read(self.reg[PC]);
}

pub fn shouldExecuteInstruction(self: *Cpu, instr: u32) bool {
    // THUMB instructions do not have the condition field at the start of each opcode
    if (self.cpsr.t)
        return true;

    const condition = @intToEnum(Condition, instr >> 28);
    self.log.print("{}", .{condition}, .{ .text_format = TF.Italic ++ TF.Underline, .ignore_indent = true });
    return self.checkCondition(condition);
}

pub fn checkCondition(self: Cpu, condition: Condition) bool {
    return switch (condition) {
        .Equal => self.cpsr.z,
        .NotEqual => !self.cpsr.z,
        .UnsignedHigherOrSame => self.cpsr.c,
        .UnsignedLower => !self.cpsr.c,
        .Negative => self.cpsr.n,
        .PositiveOrZero => !self.cpsr.n,
        .Overflow => self.cpsr.v,
        .NoOverflow => !self.cpsr.v,
        .UnsignedHigher => self.cpsr.c and !self.cpsr.z,
        .UnsignedLowerOrSame => !self.cpsr.c or self.cpsr.z,
        .GreaterOrEqual => self.cpsr.n == self.cpsr.v,
        .LessThan => self.cpsr.n != self.cpsr.v,
        .GreaterThan => !self.cpsr.z and (self.cpsr.n == self.cpsr.v),
        .LessThanOrEqual => self.cpsr.z or (self.cpsr.n != self.cpsr.v),
        .Always => true,
        else => unreachable,
    };
}

pub fn decode(self: Cpu, instr: u32) InstructionType {
    return if (self.cpsr.t)
        decodeThumb(@truncate(u16, instr))
    else
        decodeArm(instr);
}

fn decodeThumb(instr: u16) InstructionType {
    // 5.2 Add/subtract
    if (instr >> 11 == 0b00011)
        return .ThumbAddSub;

    // 5.1 Move shifted register
    if (instr >> 13 == 0b000)
        return .ThumbMoveShifted;

    // 5.3 Move/compare/add/subtract immediate
    if (instr >> 13 == 0b001)
        return .ThumbAluImmediate;

    // 5.4 ALU operations
    if (instr >> 10 == 0b010000)
        return .ThumbAluReg;

    // 5.5 Hi register operations/branch exchange
    if (instr >> 10 == 0b010001)
        return .ThumbHiRegOperationsBranchExchange;

    // 5.6 PC-relative load
    if (instr >> 11 == 0b01001)
        return .ThumbPcRelativeLoad;

    // 5.7 Load/store with register offset
    if ((instr >> 9) & 0b1111001 == 0b0101000)
        return .ThumbLoadStoreWithRegOffset;

    // 5.8 Load/store with sign-extended byte/halfword
    if ((instr >> 9) & 0b1111001 == 0b0101001)
        return .ThumbLoadStoreSignExt;

    // 5.9 Load/store with immediate offset
    if (instr >> 13 == 0b011)
        return .ThumbLoadStoreImmediateOffset;

    // 5.10 Load/store halfword
    if (instr >> 12 == 0b1000)
        return .ThumbLoadStoreHalfword;

    // 5.11 SP-relative load/store
    if (instr >> 12 == 0b1001)
        return .ThumbStackPtrRelativeLoadStore;

    // 5.12 Load address
    if (instr >> 12 == 0b1010)
        return .ThumbLoadAddr;

    // 5.13 Add offset to stack pointer
    if ((instr >> 10) & 0b111101 == 0b101100)
        return .ThumbAddOffsetToStackPtr;

    // 5.14 Push/pop registers
    if ((instr >> 10) & 0b111101 == 0b101101)
        return .ThumbPushPopReg;

    // 5.15 Multiple load/store
    if (instr >> 12 == 0b1100)
        return .ThumbLoadStoreMultiple;

    // 5.17 Software Interrupt
    if (instr >> 8 == 0b11011111)
        return .ThumbSoftwareInterrupt;

    // 5.16 Conditional branch
    if (instr >> 12 == 0b1101)
        return .ThumbBranchConditional;

    // 5.18 Unconditional branch
    if (instr >> 12 == 0b1110)
        return .ThumbBranchUnconditional;

    // 5.19 Long branch with link
    if (instr >> 12 == 0b1111)
        return .ThumbBranchLongWithLink;

    return .Unknown;
}

fn decodeArm(instr: u32) InstructionType {
    // 4.3 Branch and Exchange (BX)
    // swaps between THUMB and ARM instruction sets
    if (instr & 0x0fff_fff0 == 0x012f_ff10)
        return .BranchExchange;

    // 4.4 Branch and Branch with Link (B, BL)
    if (instr & 0x0e00_0000 == 0x0a00_0000)
        return .Branch;

    // 4.5 Data Processing
    // Simple ALU ops
    if (instr & 0x0c00_0000 == 0x0000_0000)
        return .DataProcessing;

    // 4.6 PSR Transfer (MRS, MSR)
    // allows access to the CPSR and SPSR registers
    //   MRS (transfer PSR contents to a register)
    if (instr & 0x0fbf_0fff == 0x010f_0000)
        return .MoveFromStatus;
    //   MSR (transfer register contents to PSR)
    if (instr & 0x0fbf_fff0 == 0x0129_f000)
        return .MoveToStatus;
    //   MSR (transfer register contents or immdiate value to PSR flag bits only)
    if (instr & 0x0dbf_f000 == 0x0128_f000)
        return .MoveToFlags;

    // 4.7 Multiply and Multiply-Accumulate (MUL, MLA)
    if (instr & 0x0fc0_00f0 == 0x0000_0090)
        return .Multiply;

    // 4.8 Multiply Long and Multiply-Accumulate Long (MULL,MLAL)
    if (instr & 0x0f80_00f0 == 0x0080_0090)
        return .MultiplyLong;

    // 4.9 Single Data Transfer (LDR, STR)
    // used to load/store single bytes/words of data
    if (instr & 0x0c00_0000 == 0x0400_0000)
        return .SingleDataTransfer;

    // 4.10 Halfword and Signed Data Transfer (LDRH/STRH/LDRSB/LDRSH)
    if (instr & 0x0e40_0F90 == 0x0000_0090)
        return .HalfwordDataTransferRegOffset;
    if (instr & 0x0e40_0090 == 0x0040_0090)
        return .HalfwordDataTransferImmediateOffset;

    // 4.11 Block Data Transfer (LDM, STM)
    // loads or stores any subset of registers
    if (instr & 0x0e00_0000 == 0x0800_0000)
        return .BlockDataTransfer;

    // 4.12 Single Data Swap (SWP)
    // swaps a byte/word between a register and external memory
    if (instr & 0x0fb0_0ff0 == 0x0100_0090)
        return .SingleDataSwap;

    // 4.13 Software Interrupt (SWI)
    // used to enter supervisor mode(?) in a controlled manner
    if (instr & 0x0f00_0000 == 0x0f00_0000)
        return .SoftwareInterrupt;

    // std.log.crit("unknown instruction: {X:0>8}", .{instr});
    return .Unknown;
}

pub fn branch(self: *Cpu, instr: u32) void {
    if ((instr & (1 << 24)) != 0) {
        // branch with link - save return address in LR
        self.reg[LR] = self.reg[PC] + 4;
        self.log.print("branch with link", .{}, .{});
    }

    const curr_pos = @intCast(i64, self.reg[PC]);
    const offset = @bitCast(i32, (instr & 0xFF_FFFF) << 2);
    self.reg[PC] = @intCast(u32, curr_pos + offset + 8);

    self.log.print("jumping by 0x{X}", .{offset}, .{});
}

pub fn branchExchange(self: *Cpu, instr: u32) void {
    const base_reg = instr & 0x0F;
    const toThumb = self.reg[base_reg] & 0x01 == 0x01;

    self.log.print("T={} -> T={} (reg{})", .{
        self.cpsr.t,
        toThumb,
        base_reg,
    }, .{});

    self.cpsr.t = toThumb;
    self.reg[PC] += 4;
}

pub fn blockDataTransfer(self: *Cpu, instr: u32) void {
    const BdtInstr = packed struct {
        reg_list: u16,
        base_reg: u4,
        type: enum(u1) { Store, Load },
        write_back: bool,
        load_psr_or_force_user_mode: bool,
        dir: enum(u1) { Down, Up },
        index: enum(u1) { Post, Pre },
        _: u7,
    };

    self.log.print("{}", .{@bitCast(BdtInstr, instr)}, .{});

    self.reg[PC] += 4;
}

pub fn singleDataTransfer(self: *Cpu, instr: u32) !void {
    const SdtInstr = packed struct {
        offset: u12,
        src_dst_reg: u4,
        base_reg: u4,
        type: enum(u1) { Store, Load },
        write_back: bool,
        qty: enum(u1) { Word, Byte },
        dir: enum(u1) { Down, Up },
        index: enum(u1) { Post, Pre },
        offset_type: enum(u1) { Immediate, Register },
        _: u6,
    };

    const sdt = @bitCast(SdtInstr, instr);
    // std.debug.print("       {}\n", .{sdt});

    // unsure if this is correct
    if (sdt.index == .Pre)
        self.reg[PC] += 4;

    const base_value = self.reg[sdt.base_reg];
    const offset = if (sdt.offset_type == .Immediate)
        sdt.offset
    else
        self.shiftWithField(self.reg[sdt.offset & 0x0F], @intCast(u8, sdt.offset >> 4), false);
    var mem_addr = if (sdt.dir == .Up)
        base_value + offset
    else
        base_value - offset;

    if (sdt.base_reg == PC)
        mem_addr += 4;

    self.log.print("{} at mem_addr=0x{X} (base_val=0x{X}, offset=0x{X})", .{
        sdt.type,
        mem_addr,
        base_value,
        offset,
    }, .{});

    self.log.indent();
    defer self.log.deindent();

    if (sdt.type == .Load) {
        if (sdt.qty == .Byte) {
            self.log.print(
                "reg{} <- 0x{X:0>2} (byte@0x{X:0>8})",
                .{ sdt.src_dst_reg, (try self.read(mem_addr)) & 0xFF, mem_addr },
                .{},
            );

            self.reg[sdt.src_dst_reg] = (try self.read(mem_addr)) & 0xFF;
        } else {
            self.log.print(
                "reg{} <- 0x{X:0>8} (word@0x{X:0>8})",
                .{ sdt.src_dst_reg, try self.read(mem_addr), mem_addr },
                .{},
            );

            // TODO: non-word-aligned loads
            self.reg[sdt.src_dst_reg] = try self.read(mem_addr);
        }
    } else {
        if (sdt.qty == .Byte) {
            // is this really correct?
            const byte: u32 = self.reg[sdt.src_dst_reg] & 0xFF;
            const word = byte | byte << 8 | byte << 16 | byte << 24;

            self.log.print(
                "0x{X:0>8} <- {X:0>8} (byte@reg{})",
                .{ mem_addr, word, sdt.src_dst_reg },
                .{},
            );
            self.write(mem_addr, word);
        } else {
            self.log.print(
                "0x{X:0>8} <- {X:0>8} (word@reg{})",
                .{ mem_addr, self.reg[sdt.src_dst_reg], sdt.src_dst_reg },
                .{},
            );
            self.write(mem_addr, self.reg[sdt.src_dst_reg]);
        }
    }
    // if (self.getBufForAddress(mem_addr)) |buf| {
    //     const addr = mem_addr & 0x00FF_FFFF;

    //     std.debug.print(" \n", .{});
    //     hexdump(buf, addr, .{
    //         .line_length = 16,
    //         .context = 2,
    //         .offset = mem_addr & 0xFF00_0000,
    //         .highlight = if (sdt.qty == .Word) .{ .start = addr, .end = addr + 4 } else null,
    //     });
    // }

    if (sdt.index == .Post)
        self.reg[PC] += 4;
}

const ShiftType = enum(u2) {
    LogicalLeft,
    LogicalRight,
    ArithmeticRight,
    RotateRight,
};

fn shift(self: *Cpu, value: u32, shift_amount: u5, shift_type: ShiftType) u32 {
    switch (shift_type) {
        .LogicalLeft => {
            if (shift_amount > 0)
                // TODO: only when ALU is in "logical class" (4-12)
                self.cpsr.c = (value >> @intCast(u5, 32 - @as(u6, shift_amount))) == 1;

            return std.math.shl(u32, value, shift_amount);
        },
        .LogicalRight => {
            // TODO: only when ALU is in "logical class" (4-12)
            self.cpsr.c = (value >> shift_amount - 1) == 1;

            return value >> shift_amount;
        },
        .ArithmeticRight => {
            // TODO: only when ALU is in "logical class" (4-12)
            self.cpsr.c = (value >> shift_amount - 1) == 1;

            // first bitCast to i32 to get sign extension of shift
            return @bitCast(u32, @bitCast(i32, value) >> shift_amount);
        },
        .RotateRight => {
            // TODO: rotate right extended (RRX) (4-14)
            // if (shift_amount == 0)
            //     std.math.rotr(u33, value, shift_amount);

            const output = std.math.rotr(u32, value, @intCast(u6, shift_amount));

            // TODO: only when ALU is in "logical class" (4-12)
            self.cpsr.c = output >> 31 == 1;

            return output;
        },
    }
}

fn shiftWithField(self: *Cpu, value: u32, shift_field: u8, allow_reg_shift: bool) u32 {

    // TODO: follow "Register specified shift amount" more correctly
    const shift_amount = if (allow_reg_shift and shift_field & 0x01 == 0x01)
        // shift value stored in least significant byte of a register
        self.reg[shift_field >> 4] & 0x0F
    else
        // immediate shift amount
        shift_field >> 3;

    const shift_type = @intToEnum(ShiftType, (shift_field & 0b110) >> 1);

    // TODO: set the carry output bit
    return self.shift(value, @intCast(u5, shift_amount), shift_type);
}

pub fn dataProcessing(self: *Cpu, instr: u32) void {
    const immediate = (instr & (1 << 25)) != 0;
    const set_cond_codes = (instr & (1 << 20)) != 0;
    const reg1 = (instr & 0x000F_0000) >> 16;
    const dest_reg = (instr & 0x0000_F000) >> 12;

    // 0000 = AND - Rd:= Op1 AND Op2
    // 0010 = SUB - Rd:= Op1 - Op2
    // 0011 = RSB - Rd:= Op2 - Op1
    // 0100 = ADD - Rd:= Op1 + Op2
    // 0101 = ADC - Rd:= Op1 + Op2 + C
    // 0110 = SBC - Rd:= Op1 - Op2 + C
    // 0111 = RSC - Rd:= Op2 - Op1 + C
    // 1000 = TST - set condition codes on Op1 AND Op2
    // 1001 = TEQ - set condition codes on Op1 EOR Op2
    // 1010 = CMP - set condition codes on Op1 - Op2
    // 1011 = CMN - set condition codes on Op1 + Op2
    // 1100 = ORR - Rd:= Op1 OR Op2
    // 1101 = MOV - Rd:= Op2
    // 1110 = BIC - Rd:= Op1 AND NOT Op2
    // 1111 = MVN - Rd:= NOT Op2
    const Opcode = enum(u4) {
        And,
        Eor, // XOR?
        Sub,
        RSub,
        Add,
        AddC,
        SubC,
        RSubC,
        Tst, // AND, but result is not written
        TstEq, // EOR, but result is not written
        Cmp, // SUB, but result is not written
        CmpM, // ADD, but result is not written
        Or,
        Mov, // op 1 is ignored
        BitClear,
        MovN, // op 1 is ignored

        const OpcodeType = enum { Logical, Arithmetic };

        pub fn opType(opcode: @This()) OpcodeType {
            return switch (opcode) {
                .And, .Eor, .Tst, .TstEq, .Or, .Mov, .BitClear, .MovN => .Logical,
                else => .Arithmetic,
            };
        }

        pub fn shouldWriteResult(opcode: @This()) bool {
            return switch (opcode) {
                .Tst, .TstEq, .Cmp, .CmpM => false,
                else => true,
            };
        }
    };

    const opcode = @intToEnum(Opcode, (instr & 0x01E0_0000) >> 21);
    self.log.print("{}:", .{opcode}, .{});
    self.log.indent();

    var op1: u32 = self.reg[reg1];
    if (reg1 == PC) op1 += 8;

    var op2: u32 = undefined;
    if (immediate) {
        const imm_val = @truncate(u8, instr);
        const rotate = instr >> 8 & 0x0F;

        op2 = std.math.rotr(u32, imm_val, rotate * 2);

        self.log.print("op1=0x{X} (reg1={})", .{ op1, reg1 }, .{});
        self.log.print("op2=0x{X} (imm_val=0x{X}, rot=0x{X})", .{ op2, imm_val, rotate }, .{});
        self.log.print("dest_reg={}", .{dest_reg}, .{});
        self.log.print("set_cond_codes={}", .{set_cond_codes}, .{});
    } else {
        // 4.5.2 Shifts
        const reg2 = instr & 0x0F;
        const shift_field = @truncate(u8, instr >> 4);

        var reg_val = self.reg[reg2];
        if (reg2 == PC) reg_val += 8;
        op2 = self.shiftWithField(reg_val, shift_field, true);

        self.log.print("op1=0x{X} (reg1={})", .{ op1, reg1 }, .{});
        self.log.print("op2=0x{X} (reg2={}, (val=0x{X}, shift_field=0x{X}))", .{ op2, reg2, self.reg[reg2], shift_field }, .{});
        self.log.print("dest_reg={}", .{dest_reg}, .{});
        self.log.print("set_cond_codes={}", .{set_cond_codes}, .{});
    }
    self.log.deindent();

    const result: u32 = switch (opcode) {
        .And, .Tst => op1 & op2,
        .Eor, .TstEq => op1 ^ op2,
        .Sub, .Cmp => op1 - op2,
        .RSub => op2 - op1,
        .Add, .CmpM => op1 + op2,
        .AddC => op1 + op2 + @boolToInt(self.cpsr.c),
        .SubC => op1 - op2 + @boolToInt(self.cpsr.c) - 1,
        .RSubC => op2 - op1 + @boolToInt(self.cpsr.c) - 1,
        .Or => op1 | op2,
        .Mov => op2,
        .BitClear => op1 & ~op2,
        .MovN => ~op2,
    };

    // 4.5.1 CPSR flags
    if (set_cond_codes and dest_reg != 15) {
        if (opcode.opType() == .Logical) {
            // V is unaffected
            // TODO: carry out from the barrel shifter, or preserved when the shift operation is LSL #0
            // self.cpsr.c = ?;
        } else {
            // TODO: set if an overflow occurs into bit 31 of the result?
            // self.cpsr.v = ?;
            // TODO: carry out of the ALU
            // self.cpsr.c = ?;
        }

        self.cpsr.z = result == 0;
        self.cpsr.n = result >> 31 == 1;
    }

    if (opcode.shouldWriteResult()) {
        self.log.print("reg{} <- 0x{X}", .{ dest_reg, result }, .{});
        self.reg[dest_reg] = result;
    }

    self.reg[PC] += 4;
}

pub fn thumbBranchUnconditional(self: *Cpu, instr: u16) void {
    const offset = @truncate(i12, @intCast(i32, instr << 1)) + 4;

    self.log.print("jumping by 0x{X}", .{offset}, .{});

    const new_pos = @intCast(i32, self.reg[PC]) + offset;
    self.reg[PC] = @intCast(u32, new_pos);
}

pub fn thumbBranchConditional(self: *Cpu, instr: u16) void {
    const condition = @intToEnum(Condition, @truncate(u4, instr >> 8));

    self.log.print("checking {}", .{condition}, .{});
    self.log.indent();
    defer self.log.deindent();

    if (!self.checkCondition(condition)) {
        self.log.print("not jumping!", .{}, .{});
        self.reg[PC] += 2;
        return;
    }
    const offset = @truncate(i9, @intCast(i32, instr << 1));
    self.log.print("jumping by 0x{X}", .{offset}, .{});

    const new_pos = @intCast(i32, self.reg[PC]) + offset + 4;
    self.reg[PC] = @intCast(u32, new_pos);
}

// NOTE: takes a 4 byte instruction
pub fn thumbBranchLongWithLink(self: *Cpu, instr: u32) void {
    const LongBranchInstr = packed struct {
        offset: u11,
        offset_part: enum(u1) { High, Low },
        _: u4,
    };

    const lbi1 = @bitCast(LongBranchInstr, @truncate(u16, instr));
    const lbi2 = @bitCast(LongBranchInstr, @truncate(u16, instr >> 16));
    self.log.print("lower: {}", .{lbi1}, .{});
    self.log.print("upper: {}", .{lbi2}, .{});
    self.log.indent();
    defer self.log.deindent();

    const unsigned_offset = @as(u32, lbi1.offset) << 12 | @as(u32, lbi2.offset) << 1;
    const offset = @bitCast(i23, @truncate(u23, unsigned_offset));

    self.reg[LR] = (self.reg[PC] + 4) | 0x01;

    const new_pos = @intCast(i32, self.reg[PC]) + offset + 4;
    self.log.print("jumping to 0x{X:0>8}", .{new_pos}, .{});
    self.reg[PC] = @intCast(u32, new_pos);
}

pub fn thumbPcRelativeLoad(self: *Cpu, instr: u16) void {
    const offset = (instr & 0xFF) << 2;
    const dest_reg = instr >> 8 & 0b111;

    const addr = (self.reg[PC] & 0xFFFF_FFFC) + offset + 4;
    const val = self.read(addr) catch unreachable;
    self.log.print("reg{} <- 0x{X} (word@0x{X:0>8}, offset = 0x{X})", .{ dest_reg, val, addr, offset }, .{});
    self.reg[dest_reg] = val;

    // self.log.hexdump(self.getBufForAddress(addr).?, addr & 0x00FF_FFFF, .{});

    self.reg[PC] += 2;
}

pub fn thumbMoveShifted(self: *Cpu, instr: u16) void {
    const Op = enum(u2) {
        LSL,
        LSR,
        ASR,
    };

    const MoveShiftedInstr = packed struct {
        dest: u3,
        source: u3,
        offset: u5,
        op: Op,
        _: u3,
    };

    const msi = @bitCast(MoveShiftedInstr, instr);
    self.log.print("{}", .{msi}, .{});

    const shift_type: ShiftType = switch (msi.op) {
        .LSL => .LogicalLeft,
        .LSR => .LogicalRight,
        .ASR => .ArithmeticRight,
    };
    const result = self.shift(self.reg[msi.source], msi.offset, shift_type);

    self.log.print("reg{} <- 0x{X}", .{ msi.dest, result }, .{});
    self.reg[msi.dest] = result;

    self.cpsr.z = result == 0;
    self.cpsr.n = result >> 31 == 1;

    self.reg[PC] += 2;
}

pub fn thumbHiRegOperationsBranchExchange(self: *Cpu, instr: u16) void {
    const Op = enum(u2) {
        Add,
        Compare,
        Move,
        BranchExchange,
    };

    const HiRegOpInstr = packed struct {
        dest_reg: u3,
        source_reg: u3,
        flag2: bool,
        flag1: bool,
        opcode: Op,
        _: u6,
    };

    const hroi = @bitCast(HiRegOpInstr, instr);

    self.log.print("{}", .{hroi}, .{});
    self.log.indent();
    defer self.log.deindent();

    const dest_reg = if (hroi.flag1) @as(u4, hroi.dest_reg) + 8 else hroi.dest_reg;
    const source_reg = if (hroi.flag2) @as(u4, hroi.source_reg) + 8 else hroi.source_reg;

    self.log.print("rd={}, rs={}", .{ dest_reg, source_reg }, .{});

    switch (hroi.opcode) {
        .Add => self.reg[dest_reg] += self.reg[source_reg],
        .Compare => {
            const result = self.reg[dest_reg] - self.reg[source_reg];
            // TODO: other conditions
            self.cpsr.z = result == 0;
            self.cpsr.n = result >> 31 == 1;
        },
        .Move => self.reg[dest_reg] = self.reg[source_reg],
        .BranchExchange => {
            self.reg[PC] = self.reg[source_reg] & 0xFFFF_FFFE;
            self.cpsr.t = self.reg[source_reg] & 0x01 == 0x01;
            return;
        },
    }

    self.reg[PC] += 2;
}

pub fn thumbAluImmediate(self: *Cpu, instr: u16) void {
    const Op = enum(u2) {
        Move,
        Compare,
        Add,
        Sub,
    };

    const AluImmInstr = packed struct {
        imm: u8,
        dest_reg: u3,
        opcode: Op,
        _: u3,
    };

    const aii = @bitCast(AluImmInstr, instr);
    self.log.print("{}", .{aii}, .{});
    self.log.indent();
    defer self.log.deindent();

    const result = switch (aii.opcode) {
        .Move => aii.imm,
        .Compare, .Sub => self.reg[aii.dest_reg] - aii.imm,
        .Add => self.reg[aii.dest_reg] + aii.imm,
    };

    self.cpsr.z = result == 0;
    self.cpsr.n = result >> 31 == 1;

    if (aii.opcode != .Compare) {
        self.log.print("reg{} <- 0x{X:0>2}", .{ aii.dest_reg, result }, .{});
        self.reg[aii.dest_reg] = result;
    }

    self.reg[PC] += 2;
}

pub fn thumbAluReg(self: *Cpu, instr: u16) void {
    const Op = enum(u4) {
        And,
        Eor,
        Lsl,
        Lsr,
        Asr,
        Adc,
        Sbc,
        Ror,
        Tst,
        Neg,
        Cmp,
        Cmn,
        Orr,
        Mul,
        Bic,
        Mvn,

        pub fn setDest(opcode: @This()) bool {
            return switch (opcode) {
                .Tst, .Cmp, .Cmn => false,
                else => true,
            };
        }
    };

    const AluRegInstr = packed struct {
        dest_reg: u3,
        source_reg: u3,
        opcode: Op,
        _: u6,
    };

    const ari = @bitCast(AluRegInstr, instr);
    self.log.print("{}", .{ari}, .{});

    const op1 = self.reg[ari.dest_reg];
    const op2 = self.reg[ari.source_reg];
    self.log.print("op1=0x{X} op2=0x{X}", .{ op1, op2 }, .{});

    self.log.indent();
    defer self.log.deindent();

    const result = switch (ari.opcode) {
        .And, .Tst => op1 & op2,
        .Eor => op1 ^ op2,
        .Lsl => self.shift(op1, @truncate(u5, op2), .LogicalLeft),
        .Lsr => self.shift(op1, @truncate(u5, op2), .LogicalRight),
        .Asr => self.shift(op1, @truncate(u5, op2), .ArithmeticRight),
        .Adc => op1 + op2 + @boolToInt(self.cpsr.c),
        .Sbc => op1 - op2 - @boolToInt(!self.cpsr.c),
        .Ror => self.shift(op1, @truncate(u5, op2), .RotateRight),
        .Neg => @bitCast(u32, -@bitCast(i32, op2)),
        .Cmp => op1 - op2,
        .Cmn => op1 + op2,
        .Orr => op1 | op2,
        .Mul => @truncate(u32, op1 * op2),
        .Bic => op1 & ~op2,
        .Mvn => ~op2,
    };

    self.cpsr.z = result == 0;
    self.cpsr.n = result >> 31 == 1;

    if (ari.opcode.setDest()) {
        self.log.print("reg{} <- 0x{X:0>8}", .{ ari.dest_reg, result }, .{});
        self.reg[ari.dest_reg] = result;
    }

    self.reg[PC] += 2;
}

pub fn thumbAddSub(self: *Cpu, instr: u16) void {
    const AddSubInstr = packed struct {
        dest_reg: u3,
        op1_reg: u3,
        op2_reg: u3,
        opcode: enum(u1) { Add, Sub },
        imm: bool,
        _: u5,
    };

    const asi = @bitCast(AddSubInstr, instr);
    self.log.print("{}", .{asi}, .{});
    self.log.indent();
    defer self.log.deindent();

    const op2_val = if (asi.imm) asi.op2_reg else self.reg[asi.op2_reg];
    const result = switch (asi.opcode) {
        .Add => self.reg[asi.op1_reg] + op2_val,
        .Sub => self.reg[asi.op1_reg] - op2_val,
    };

    self.cpsr.z = result == 0;
    self.cpsr.n = result >> 31 == 1;

    self.log.print("reg{} <- 0x{X:0>8}", .{ asi.dest_reg, result }, .{});
    self.reg[asi.dest_reg] = result;

    self.reg[PC] += 2;
}

pub fn thumbLoadStoreMultiple(self: *Cpu, instr: u16) void {
    const LoadStoreMultipleInstr = packed struct {
        reg_list: u8,
        base_reg: u3,
        dir: enum(u1) { Store, Load },
        _: u4,
    };

    const lsmi = @bitCast(LoadStoreMultipleInstr, instr);
    self.log.print("{}", .{lsmi}, .{});
    self.log.indent();
    defer self.log.deindent();

    var reg: u4 = 0;
    var addr: u32 = self.reg[lsmi.base_reg];
    while (reg < 8) : (reg += 1) {
        if ((lsmi.reg_list >> @intCast(u3, reg)) & 0x01 == 0x01) {
            if (lsmi.dir == .Store) {
                self.log.print("0x{X:0>8} <- 0x{X:0>8} (reg{})", .{ addr, self.reg[reg], reg }, .{});
                self.write(addr, self.reg[reg]);
            } else {
                self.log.print("reg{} <- 0x{X:0>8} (word@0x{X:0>8})", .{ reg, self.reg[reg], addr }, .{});
                self.reg[reg] = self.read(addr) catch unreachable;
            }

            addr += 4;
        }
    }

    // if (self.getBufForAddress(self.reg[lsmi.base_reg])) |buf| {
    //     const hex_addr = self.reg[lsmi.base_reg] & 0x00FF_FFFF;

    //     self.log.print("", .{}, .{});
    //     self.log.hexdump(buf, hex_addr, .{
    //         .line_length = 8,
    //         .context = 0,
    //         .offset = self.reg[lsmi.base_reg] & 0xFF00_0000,
    //     });
    // }

    self.reg[lsmi.base_reg] = addr;

    self.reg[PC] += 2;
}

pub fn thumbLoadStoreImmediateOffset(self: *Cpu, instr: u16) void {
    const LoadStoreImmOffsetInstr = packed struct {
        source_dest_reg: u3,
        base_reg: u3,
        offset: u5,
        dir: enum(u1) { Store, Load },
        qty: enum(u1) { Word, Byte },
        _: u3,
    };

    const lsioi = @bitCast(LoadStoreImmOffsetInstr, instr);
    self.log.print("{}", .{lsioi}, .{});
    self.log.indent();
    defer self.log.deindent();

    const offset = if (lsioi.qty == .Word)
        @bitCast(i7, @as(u7, lsioi.offset) << 2)
    else
        @as(i7, @bitCast(i5, lsioi.offset));

    const addr = @intCast(u32, @intCast(i32, self.reg[lsioi.base_reg]) + offset);

    if (lsioi.dir == .Store) {
        var reg_val = self.reg[lsioi.source_dest_reg];
        if (lsioi.qty == .Byte) {
            reg_val &= 0xFF;
            self.log.print("0x{X:0>8} <- 0x{X:0>2} (byte@reg{})", .{ addr, reg_val, lsioi.source_dest_reg }, .{});
        } else {
            self.log.print("0x{X:0>8} <- 0x{X:0>8} (word@reg{})", .{ addr, reg_val, lsioi.source_dest_reg }, .{});
        }
        self.write(addr, reg_val);
    } else {
        var addr_val = self.read(addr) catch unreachable;
        if (lsioi.qty == .Byte) {
            addr_val &= 0xFF;
            self.log.print("reg{} <- 0x{X:0>2} (byte@0x{X:0>8})", .{ lsioi.source_dest_reg, addr_val, addr }, .{});
        } else {
            self.log.print("reg{} <- 0x{X:0>8} (word@0x{X:0>8})", .{ lsioi.source_dest_reg, addr_val, addr }, .{});
        }

        self.reg[lsioi.source_dest_reg] = addr_val;
    }

    self.reg[PC] += 2;
}

pub fn thumbLoadStoreHalfword(self: *Cpu, instr: u16) void {
    const LoadStoreHalfwordInstr = packed struct {
        source_dest_reg: u3,
        base_reg: u3,
        offset: u5,
        dir: enum(u1) { Store, Load },
        _: u4,
    };

    const lshi = @bitCast(LoadStoreHalfwordInstr, instr);
    self.log.print("{}", .{lshi}, .{});
    self.log.indent();
    defer self.log.deindent();

    self.log.flush();

    const offset = @bitCast(i6, @as(u6, lshi.offset) << 1);
    const addr = @intCast(u32, @intCast(i32, self.reg[lshi.base_reg]) + offset);

    if (lshi.dir == .Store) {
        var reg_val = @truncate(u16, self.reg[lshi.source_dest_reg]);
        self.log.print("0x{X:0>8} <- 0x{X:0>4} (halfword@reg{})", .{ addr, reg_val, lshi.source_dest_reg }, .{});
        self.writeHalfword(addr, reg_val);
    } else {
        var addr_val = @truncate(u16, self.read(addr) catch unreachable);
        self.log.print("reg{} <- 0x{X:0>4} (halfword@0x{X:0>8})", .{ lshi.source_dest_reg, addr_val, addr }, .{});
        self.reg[lshi.source_dest_reg] = addr_val;
    }

    self.reg[PC] += 2;
}

fn pushToStack(self: *Cpu, val: u32) void {
    self.reg[SP] -= 4;
    self.log.print("stack push: 0x{X:0>8} <- 0x{X:0>8}", .{ self.reg[SP], val }, .{});
    self.write(self.reg[SP], val);
}

fn popFromStack(self: *Cpu) u32 {
    const val = self.read(self.reg[SP]) catch unreachable;
    self.log.print("stack pop: 0x{X:0>8} (word@0x{X:0>8})", .{ val, self.reg[SP] }, .{});
    self.reg[SP] += 4;

    return val;
}

pub fn thumbPushPopReg(self: *Cpu, instr: u16) void {
    const reg_list = instr & 0xFF;
    const store_load_lr = (instr >> 8) & 0x01 == 0x01;
    const dir = @intToEnum(enum(u1) { Store, Load }, (instr >> 11) & 0x01);

    if (store_load_lr) {
        self.log.print("  lr: ", .{}, .{ .newline = false });
        if (dir == .Store)
            self.pushToStack(self.reg[LR])
        else
            self.reg[LR] = self.popFromStack();
    }

    var i: u4 = 0;
    while (i < 8) : (i += 1) {
        const reg = if (dir == .Store) 8 - i else i;
        if ((reg_list >> reg) & 0x01 == 0x01) {
            self.log.print("reg{}: ", .{reg}, .{ .newline = false });
            if (dir == .Store)
                self.pushToStack(self.reg[reg])
            else
                self.reg[reg] = self.popFromStack();
        }
    }

    self.reg[PC] += 2;
}

fn lcdControl(self: *Cpu, val: u16) void {
    const LcdControl = packed struct {
        bg_mode: u3,
        cgb_mode: u1,
        display_frame: u1,
        h_blank_interval_free: bool,
        obj_char_vram_mapping: enum(u1) { TwoDim, OneDim },
        forced_blank: bool,
        screen_display_bg0: bool,
        screen_display_bg1: bool,
        screen_display_bg2: bool,
        screen_display_bg3: bool,
        screen_display_obj: bool,
        window_0_display: bool,
        window_1_display: bool,
        obj_window_display: bool,
    };

    const lc = @bitCast(LcdControl, val);
    self.log.print("{}", .{lc}, .{});
    self.log.indent();
    defer self.log.deindent();

    self.log.print("setting mode to mode {}", .{lc.bg_mode}, .{});
}

pub fn dumpRegisters(self: *Cpu) void {
    self.log.startBox(74, "Register Dump");
    defer self.log.stopBox();

    self.log.print("CPSR: N={} Z={} C={} V={}  |  I={} F={}  |  T={}  |  Mode={b:0>5}", .{
        @boolToInt(self.cpsr.n),
        @boolToInt(self.cpsr.z),
        @boolToInt(self.cpsr.c),
        @boolToInt(self.cpsr.v),
        @boolToInt(self.cpsr.i),
        @boolToInt(self.cpsr.f),
        @boolToInt(self.cpsr.t),
        self.cpsr.mode,
    }, .{});

    for (self.reg[0..16]) |reg, i| {
        const cell_tf: ?[]const u8 = if (reg != self.prev_reg[i]) TF.YellowBg else null;
        self.log.print("{X:0>8}", .{reg}, .{ .text_format = cell_tf, .newline = false });
        self.log.print(" ", .{}, .{ .newline = i == 7 });

        self.prev_reg[i] = reg;
    }
}

pub fn incrementProgramCounter(self: *Cpu) void {
    if (self.cpsr.t)
        self.reg[PC] += 2
    else
        self.reg[PC] += 4;
}
