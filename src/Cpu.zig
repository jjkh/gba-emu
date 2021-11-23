const std = @import("std");
const Cpu = @This();

const C = @import("utility.zig").Colour;

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
    Unknown,
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

// 3.7 Registers
// ARM7TDMI has a total of 37 registers - 31 general-purpose 32-bit registers and six
// status registers - but these cannot all be seen at once. The processor state and
// operating mode dictate which registers are available to the programmer.
reg: [16]u32 = std.mem.zeroes([16]u32),

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
work_ram: [0xC000]u8 = std.mem.zeroes([0xC000]u8),
game_pak: []const u8 = undefined,

fn readU32(mem: []const u8, offset: u32) u32 {
    return @ptrCast(*const u32, @alignCast(4, &mem.ptr[offset])).*;
}

pub fn read(self: Cpu, addr: u32) !u32 {
    return switch (addr >> 24) {
        0x00 => readU32(&self.rom, addr),
        0x03 => readU32(&self.work_ram, addr - 0x0300_0000),
        0x08 => readU32(self.game_pak, addr - 0x0800_0000),
        // 0x0A => readU32(self.game_pak, addr - 0x0A00_0000),
        // 0x0C => readU32(self.game_pak, addr - 0x0C00_0000),
        else => {
            std.log.crit("unimplemented address: {X:0>8}", .{addr});
            return error.UnimplementedAddress;
        },
    };
}

pub fn getNextInstruction(self: Cpu) !u32 {
    return self.read(self.reg[PC]);
}

pub fn checkCondition(self: Cpu, instr: u32) bool {
    const condition = @intToEnum(Condition, instr >> 28);
    std.debug.print(C.Italic ++ C.Underline ++ "{}" ++ C.Reset ++ "\n", .{condition});

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

pub fn decode(instr: u32) InstructionType {
    // 4.3 Branch and Exchange (BX)
    // swaps between THUMB and ARM instruction sets
    if ((instr & 0x0fff_fff0) == 0x012f_ff10)
        return .BranchExchange;

    // 4.4 Branch and Branch with Link (B, BL)
    if ((instr & 0x0e00_0000) == 0x0a00_0000)
        return .Branch;

    // 4.5 Data Processing
    // Simple ALU ops
    if ((instr & 0x0c00_0000) == 0x0000_0000)
        return .DataProcessing;

    // 4.6 PSR Transfer (MRS, MSR)
    // allows access to the CPSR and SPSR registers
    //   MRS (transfer PSR contents to a register)
    if ((instr & 0x0fbf_0fff) == 0x010f_0000)
        return .MoveFromStatus;
    //   MSR (transfer register contents to PSR)
    if ((instr & 0x0fbf_fff0) == 0x0129_f000)
        return .MoveToStatus;
    //   MSR (transfer register contents or immdiate value to PSR flag bits only)
    if ((instr & 0x0dbf_f000) == 0x0128_f000)
        return .MoveToFlags;

    // 4.7 Multiply and Multiply-Accumulate (MUL, MLA)
    if ((instr & 0x0fc0_00f0) == 0x0000_0090)
        return .Multiply;

    // 4.8 Multiply Long and Multiply-Accumulate Long (MULL,MLAL)
    if ((instr & 0x0f80_00f0) == 0x0080_0090)
        return .MultiplyLong;

    // 4.9 Single Data Transfer (LDR, STR)
    // used to load/store single bytes/words of data
    if ((instr & 0x0c00_0000) == 0x0400_0000)
        return .SingleDataTransfer;

    // 4.10 Halfword and Signed Data Transfer (LDRH/STRH/LDRSB/LDRSH)
    if ((instr & 0x0e40_0F90) == 0x0000_0090)
        return .HalfwordDataTransferRegOffset;
    if ((instr & 0x0e40_0090) == 0x0040_0090)
        return .HalfwordDataTransferImmediateOffset;

    // 4.11 Block Data Transfer (LDM, STM)
    // loads or stores any subset of registers
    if ((instr & 0x0e00_0000) == 0x0800_0000)
        return .BlockDataTransfer;

    // 4.12 Single Data Swap (SWP)
    // swaps a byte/word between a register and external memory
    if ((instr & 0x0fb0_0ff0) == 0x0100_0090)
        return .SingleDataSwap;

    // 4.13 Software Interrupt (SWI)
    // used to enter supervisor mode(?) in a controlled manner
    if ((instr & 0x0f00_0000) == 0x0f00_0000)
        return .SoftwareInterrupt;

    // std.log.crit("unknown instruction: {X:0>8}", .{instr});
    return .Unknown;
}

pub fn branch(self: *Cpu, instr: u32) void {
    if ((instr & (1 << 24)) != 0) {
        // branch with link - save return address in LR
        self.reg[LR] = self.reg[PC] + 4;
        std.debug.print("       branch with link\n", .{});
    }

    const curr_pos = @intCast(i64, self.reg[PC]);
    const offset = @bitCast(i32, (instr & 0xFF_FFFF) << 2);
    self.reg[PC] = @intCast(u32, curr_pos + offset);

    std.debug.print("       jumping by 0x{X}\n", .{offset});
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

    std.debug.print("       {}\n", .{@bitCast(BdtInstr, instr)});

    self.reg[PC] += 4;
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

    var op1: u32 = self.reg[reg1];
    var op2: u32 = undefined;
    if (immediate) {
        const imm_val = @intCast(u8, instr & 0xFF);
        const rotate = (instr & 0x0F00) >> 8;

        op2 = std.math.rotr(u32, imm_val, rotate * 2);
        std.debug.print(
            \\       {}:
            \\           op1=0x{X} (reg1={})
            \\           op2=0x{X} (imm_val=0x{X}, rot=0x{X})
            \\           dest_reg={}
            \\           set_cond_codes={}
            \\
        , .{
            opcode,
            op1,
            reg1,
            op2,
            imm_val,
            rotate,
            dest_reg,
            set_cond_codes,
        });
    } else {
        // 4.5.2 Shifts
        const reg2 = instr & 0x0F;
        const shift = (instr & 0x0FF0) >> 4;

        const ShiftType = enum(u2) {
            LogicalLeft,
            LogicalRight,
            ArithmeticRight,
            RotateRight,
        };

        const shift_val = if (shift & 0x01 == 0x01)
            // shift value stored in bottom half of a register
            self.reg[shift >> 4] & 0xFF
        else
            // immediate shift amount
            shift >> 3;

        const shift_type = @intToEnum(ShiftType, (shift & 0b110) >> 1);

        // TODO: set the carry output bit
        op2 = switch (shift_type) {
            .LogicalLeft => std.math.shl(u32, self.reg[reg2], shift_val),
            .LogicalRight => std.math.shr(u32, self.reg[reg2], shift_val),
            // unsure if this is right...
            .ArithmeticRight => @intCast(u32, std.math.shr(i32, @intCast(i32, self.reg[reg2]), shift_val)),
            .RotateRight => std.math.rotr(u32, self.reg[reg2], shift_val),
        };

        std.debug.print(
            \\       {}:
            \\           op1=0x{X} (reg1={})
            \\           op2=0x{X} (reg2={}, (val=0x{X}, shift={} by 0x{X}))
            \\           dest_reg={}
            \\           set_cond_codes={}
            \\
        , .{
            opcode,
            op1,
            reg1,
            op2,
            reg2,
            self.reg[reg2],
            shift_type,
            shift_val,
            dest_reg,
            set_cond_codes,
        });
    }

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
        std.debug.print("       reg{} <- 0x{X}\n", .{ dest_reg, result });
        self.reg[dest_reg] = result;
    }

    self.reg[PC] += 4;
}

pub fn dumpRegisters(self: Cpu) void {
    std.debug.print("\n+- Register Dump ------------------------------------------------------------------+\n", .{});
    std.debug.print("| CPSR: N={} Z={} C={} V={}  |  I={} F={}  |  T={}  |  Mode={b:0>5}                         |\n", .{
        @boolToInt(self.cpsr.n),
        @boolToInt(self.cpsr.z),
        @boolToInt(self.cpsr.c),
        @boolToInt(self.cpsr.v),
        @boolToInt(self.cpsr.i),
        @boolToInt(self.cpsr.f),
        @boolToInt(self.cpsr.t),
        self.cpsr.mode,
    });

    std.debug.print("| ", .{});
    for (self.reg[0..8]) |reg|
        std.debug.print("{X:0>8}  ", .{reg});
    std.debug.print(" |\n", .{});

    std.debug.print("| ", .{});
    for (self.reg[8..16]) |reg|
        std.debug.print("{X:0>8}  ", .{reg});
    std.debug.print(" |\n", .{});
    std.debug.print("+----------------------------------------------------------------------------------+\n\n", .{});
}
