//! Bounded DNS views. Input storage must remain immutable while a Packet lives.
const std = @import("std");
pub const names = @import("wire/name.zig");
pub const rdata = @import("wire/rdata.zig");
pub const Encoder = @import("wire/encoder.zig").Encoder;
pub const rewrite = @import("wire/rewrite.zig");
pub const Name = names.Name;
pub const message_bytes_max = 65535;
pub const records_max = (message_bytes_max - 12) / 11;
pub const Error = error{
    Truncated,
    LabelTooLong,
    NameTooLong,
    InvalidPointer,
    CompressionForbidden,
    InvalidName,
    MessageTooLarge,
    InvalidCounts,
    TrailingData,
    InvalidRecord,
    InvalidOption,
    DuplicateOpt,
    InvalidOpt,
    InvalidCookie,
    NoSpace,
    RewriteTooLarge,
    InvalidOrder,
};
pub const Section = enum(u2) { question, answer, authority, additional };
pub const Flag = enum(u16) {
    response = 0x8000,
    authoritative = 0x0400,
    truncated = 0x0200,
    recursion_desired = 0x0100,
    recursion_available = 0x0080,
    authenticated = 0x0020,
    checking_disabled = 0x0010,
};

pub const Header = struct {
    id: u16 = 0,
    bits: u16 = 0,
    counts: [4]u16 = @splat(0),

    pub fn decode(data: []const u8) Error!Header {
        if (data.len < 12) return error.Truncated;
        var header: Header = .{ .id = integer(u16, data[0..2]), .bits = integer(u16, data[2..4]) };
        for (&header.counts, 0..) |*count, index| {
            count.* = integer(u16, data[4 + index * 2 ..][0..2]);
        }
        return header;
    }

    pub fn encode(self: *const Header, data: []u8) Error!void {
        if (data.len < 12) return error.NoSpace;
        put(u16, data[0..2], self.id);
        put(u16, data[2..4], self.bits);
        for (self.counts, 0..) |count, index| put(u16, data[4 + index * 2 ..][0..2], count);
    }

    pub fn opcode(self: *const Header) u4 {
        return @truncate(self.bits >> 11);
    }

    pub fn has(self: *const Header, flag: Flag) bool {
        return self.bits & @intFromEnum(flag) != 0;
    }
};

pub const Question = struct { name: u16, kind: u16, class: u16 };
pub const Record = struct {
    owner: u16,
    kind: u16,
    class: u16,
    ttl_s: u32,
    data_start: u16,
    data_end: u16,
    section: Section,
};

pub const Packet = struct {
    bytes: []const u8,
    header: Header,
    boundaries: names.Boundaries,
    question_end: u16,
    record_count: u16,
    records: [records_max]Record,
    opt: ?u16,

    /// On error, no fields of target may be consumed. No allocation occurs.
    pub fn parse(target: *Packet, bytes: []const u8) Error!void {
        if (bytes.len > message_bytes_max) return error.MessageTooLarge;
        const header = try Header.decode(bytes);
        const record_count = @as(u32, header.counts[1]) +
            @as(u32, header.counts[2]) + @as(u32, header.counts[3]);
        const minimum = @as(u32, header.counts[0]) * 5 + record_count * 11;
        if (minimum > bytes.len - 12) return error.InvalidCounts;
        target.bytes = bytes;
        target.header = header;
        target.boundaries.init();
        target.record_count = 0;
        target.opt = null;
        var cursor: usize = 12;
        for (0..header.counts[0]) |_| _ = try target.readQuestion(&cursor);
        target.question_end = @intCast(cursor);
        for ([_]Section{ .answer, .authority, .additional }) |section| {
            for (0..header.counts[@intFromEnum(section)]) |_| {
                const record = &target.records[target.record_count];
                try target.readRecord(record, &cursor, section);
                var parts: rdata.Parts = undefined;
                try rdata.parse(&parts, target, record);
                if (record.kind == 41) try target.readOpt(record);
                target.record_count += 1;
            }
        }
        if (cursor != bytes.len) return error.TrailingData;
    }

    pub fn readQuestion(self: *Packet, cursor: *usize) Error!Question {
        var expanded: Name = undefined;
        const start = cursor.*;
        cursor.* = try names.decode(
            &expanded,
            self.bytes,
            start,
            self.bytes.len,
            &self.boundaries,
            .allowed,
        );
        const fields = try take(self.bytes, cursor, 4);
        return .{
            .name = @intCast(start),
            .kind = integer(u16, fields[0..2]),
            .class = integer(u16, fields[2..4]),
        };
    }

    fn readRecord(self: *Packet, record: *Record, cursor: *usize, section: Section) Error!void {
        var expanded: Name = undefined;
        const owner = cursor.*;
        cursor.* = try names.decode(
            &expanded,
            self.bytes,
            owner,
            self.bytes.len,
            &self.boundaries,
            .allowed,
        );
        const fields = try take(self.bytes, cursor, 10);
        const start = cursor.*;
        _ = try take(self.bytes, cursor, integer(u16, fields[8..10]));
        record.* = .{
            .owner = @intCast(owner),
            .kind = integer(u16, fields[0..2]),
            .class = integer(u16, fields[2..4]),
            .ttl_s = integer(u32, fields[4..8]),
            .data_start = @intCast(start),
            .data_end = @intCast(cursor.*),
            .section = section,
        };
    }

    pub fn name(self: *const Packet, target: *Name, offset: u16) Error!void {
        var boundaries = self.boundaries;
        _ = try names.decode(target, self.bytes, offset, self.bytes.len, &boundaries, .allowed);
    }

    fn readOpt(self: *Packet, record: *const Record) Error!void {
        if (self.opt != null) return error.DuplicateOpt;
        if (record.section != .additional) return error.InvalidOpt;
        if (self.bytes[record.owner] != 0) return error.InvalidOpt;
        var options: Options = .{ .bytes = self.bytes[record.data_start..record.data_end] };
        var cookie: ?[]const u8 = null;
        while (try options.next()) |option| {
            if (option.code == 10) {
                if (cookie != null) return error.InvalidCookie;
                try validateCookie(option.data);
                cookie = option.data;
            }
        }
        self.opt = self.record_count;
    }
};

pub const Option = struct { code: u16, data: []const u8 };
pub const Options = struct {
    bytes: []const u8,
    cursor: usize = 0,

    pub fn next(self: *Options) Error!?Option {
        if (self.cursor == self.bytes.len) return null;
        const fields = take(self.bytes, &self.cursor, 4) catch return error.InvalidOption;
        const bytes = take(self.bytes, &self.cursor, integer(u16, fields[2..4])) catch
            return error.InvalidOption;
        return .{ .code = integer(u16, fields[0..2]), .data = bytes };
    }
};

pub fn validateCookie(bytes: []const u8) Error!void {
    // RFC 7873 §4: eight client bytes, optionally eight to 32 server bytes.
    if (bytes.len == 8) return;
    if (bytes.len < 16) return error.InvalidCookie;
    if (bytes.len > 40) return error.InvalidCookie;
}

pub const Malformed = union(enum) { drop, formerr: Header };
pub const Query = union(enum) { accepted, drop, reply: Header };

/// Callers use target only for accepted queries. Error replies contain no records.
pub fn query(target: *Packet, bytes: []const u8) Query {
    target.parse(bytes) catch {
        return switch (malformed(bytes)) {
            .drop => .drop,
            .formerr => |header| .{ .reply = header },
        };
    };
    if (target.header.opcode() != 0) {
        var header = target.header;
        header.bits = (header.bits & 0x7910) | 0x8004;
        header.counts = @splat(0);
        return .{ .reply = header };
    }
    if (target.header.counts[0] != 1) return .{ .reply = malformed(bytes).formerr };
    if (target.header.has(.response)) return .{ .reply = malformed(bytes).formerr };
    return .accepted;
}

pub fn malformed(bytes: []const u8) Malformed {
    var header = Header.decode(bytes) catch return .drop;
    header.bits = (header.bits & 0x7900) | 0x8001;
    header.counts = @splat(0);
    return .{ .formerr = header };
}

pub fn take(bytes: []const u8, cursor: *usize, length: usize) Error![]const u8 {
    if (cursor.* > bytes.len) return error.Truncated;
    if (length > bytes.len - cursor.*) return error.Truncated;
    const result = bytes[cursor.*..][0..length];
    cursor.* += length;
    return result;
}

pub fn integer(comptime T: type, bytes: []const u8) T {
    return std.mem.readInt(T, bytes[0..@sizeOf(T)], .big);
}

pub fn put(comptime T: type, bytes: []u8, value: T) void {
    std.mem.writeInt(T, bytes[0..@sizeOf(T)], value, .big);
}

/// RFC 1035 §4.2.2: framing accepts coalesced input and retains partial frames.
pub fn frame(bytes: []const u8) Error!?struct { message: []const u8, consumed: usize } {
    if (bytes.len < 2) return null;
    const length: usize = integer(u16, bytes[0..2]);
    if (length < 12) return error.Truncated;
    if (bytes.len < length + 2) return null;
    return .{ .message = bytes[2..][0..length], .consumed = length + 2 };
}

pub fn framePrefix(target: []u8, length: usize) Error!void {
    if (length > message_bytes_max) return error.MessageTooLarge;
    if (length < 12) return error.Truncated;
    if (target.len < 2) return error.NoSpace;
    put(u16, target[0..2], @intCast(length));
}
