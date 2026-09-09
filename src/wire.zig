//! Bounded DNS views. Input storage must remain immutable while a Packet lives.
const std = @import("std");
const builtin = @import("builtin");

const equivalent_module = @import("testing/equivalent.zig");
const fixture = @import("testing/wire.zig");
pub const Encoder = @import("wire/encoder.zig").Encoder;
pub const names = @import("wire/name.zig");
pub const Name = names.Name;
pub const rdata = @import("wire/rdata.zig");
pub const rewrite = @import("wire/rewrite.zig");

const wire = @This();
/// DNS TYPE values remain open to unknown and private-use records.
pub const RecordType = enum(u16) {
    a = 1,
    ns = 2,
    md = 3,
    mf = 4,
    cname = 5,
    soa = 6,
    mb = 7,
    mg = 8,
    mr = 9,
    null_record = 10,
    wks = 11,
    ptr = 12,
    hinfo = 13,
    minfo = 14,
    mx = 15,
    txt = 16,
    rp = 17,
    afsdb = 18,
    rt = 21,
    nsap_ptr = 23,
    sig = 24,
    px = 26,
    aaaa = 28,
    nxt = 30,
    srv = 33,
    naptr = 35,
    kx = 36,
    dname = 39,
    opt = 41,
    ds = 43,
    rrsig = 46,
    nsec = 47,
    dnskey = 48,
    nsec3 = 50,
    tlsa = 52,
    svcb = 64,
    https = 65,
    spf = 99,
    any = 255,
    _,
};

pub const header_bytes = 12;
pub const frame_prefix_bytes = @sizeOf(u16);
pub const question_fields_bytes = 2 * @sizeOf(u16);
pub const question_bytes_min = 1 + question_fields_bytes;
pub const record_fields_bytes = 3 * @sizeOf(u16) + @sizeOf(u32);
pub const record_bytes_min = 1 + record_fields_bytes;
pub const opt_record_bytes = 1 + record_fields_bytes;
pub const option_header_bytes = 2 * @sizeOf(u16);
pub const message_bytes_max = 65535;
pub const records_max = (message_bytes_max - header_bytes) / record_bytes_min;
pub const class_in: u16 = 1;
pub const udp_payload_bytes_default: u16 = 512;
pub const upstream_payload_bytes: u16 = 1232;
pub const cookie_option_code: u16 = 10;
pub const cookie_client_bytes = 8;
pub const cookie_server_bytes_min = 8;
pub const cookie_server_bytes_max = 32;
pub const cookie_bytes_max = cookie_client_bytes + cookie_server_bytes_max;
pub const cookie_option_bytes_max = option_header_bytes + cookie_bytes_max;
pub const edns_dnssec_ok: u16 = 0x8000;
pub const edns_rcode_shift = 24;
pub const edns_version_shift = 16;
pub const opcode_mask: u16 = 0x7800;
pub const request_flags_mask = Flag.mask(&.{ .recursion_desired, .checking_disabled });

pub const Cookie = [cookie_option_bytes_max]u8;

pub const Rcode = enum(u4) {
    noerror = 0,
    formerr = 1,
    servfail = 2,
    nxdomain = 3,
    notimp = 4,
    refused = 5,
    _,
};

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

pub const Section = enum(u2) {
    question,
    answer,
    authority,
    additional,
};

pub const Flag = enum(u16) {
    response = 0x8000,
    authoritative = 0x0400,
    truncated = 0x0200,
    recursion_desired = 0x0100,
    recursion_available = 0x0080,
    authenticated = 0x0020,
    checking_disabled = 0x0010,

    pub fn mask(comptime flags: []const Flag) u16 {
        return comptime bits: {
            var value: u16 = 0;
            for (flags) |flag| value |= @intFromEnum(flag);
            break :bits value;
        };
    }
};

pub const Header = struct {
    id: u16 = 0,
    bits: u16 = 0,
    counts: [4]u16 = @splat(0),

    pub fn decode(data: []const u8) Error!Header {
        if (data.len < header_bytes) return error.Truncated;
        var header: Header = .{ .id = integer(u16, data[0..2]), .bits = integer(u16, data[2..4]) };
        for (&header.counts, 0..) |*count, index| {
            count.* = integer(u16, data[4 + index * 2 ..][0..2]);
        }
        return header;
    }

    pub fn encode(self: *const Header, data: []u8) Error!void {
        if (data.len < header_bytes) return error.NoSpace;
        put(u16, data[0..2], self.id);
        put(u16, data[2..4], self.bits);
        for (self.counts, 0..) |count, index| put(u16, data[4 + index * 2 ..][0..2], count);
    }

    pub fn opcode(self: *const Header) u4 {
        return @truncate(self.bits >> 11);
    }

    pub fn rcode(self: *const Header) Rcode {
        return @enumFromInt(@as(u4, @truncate(self.bits)));
    }

    pub fn has(self: *const Header, flag: Flag) bool {
        return self.bits & @intFromEnum(flag) != 0;
    }
};

pub const Question = struct {
    name: u16,
    kind: RecordType,
    class: u16,
};

pub const Record = struct {
    owner: u16,
    kind: RecordType,
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
        const minimum = @as(u32, header.counts[0]) * question_bytes_min +
            record_count * record_bytes_min;
        if (minimum > bytes.len - header_bytes) return error.InvalidCounts;
        target.bytes = bytes;
        target.header = header;
        target.boundaries.init();
        target.record_count = 0;
        target.opt = null;
        var cursor: usize = header_bytes;
        for (0..header.counts[0]) |_| _ = try target.readQuestion(&cursor);
        target.question_end = @intCast(cursor);
        for ([_]Section{ .answer, .authority, .additional }) |section| {
            for (0..header.counts[@intFromEnum(section)]) |_| {
                const record = &target.records[target.record_count];
                try target.readRecord(record, &cursor, section);
                var parts: rdata.Parts = undefined;
                try rdata.parse(&parts, target, record);
                if (record.kind == .opt) try target.readOpt(record);
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
        const fields = try take(self.bytes, cursor, question_fields_bytes);
        return .{
            .name = @intCast(start),
            .kind = @enumFromInt(integer(u16, fields[0..2])),
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
        const fields = try take(self.bytes, cursor, record_fields_bytes);
        const start = cursor.*;
        _ = try take(self.bytes, cursor, integer(u16, fields[8..10]));
        record.* = .{
            .owner = @intCast(owner),
            .kind = @enumFromInt(integer(u16, fields[0..2])),
            .class = integer(u16, fields[2..4]),
            .ttl_s = integer(u32, fields[4..8]),
            .data_start = @intCast(start),
            .data_end = @intCast(cursor.*),
            .section = section,
        };
    }

    pub fn name(self: *const Packet, target: *Name, offset: u16) Error!void {
        _ = try names.read(target, self.bytes, offset, self.bytes.len, &self.boundaries, .allowed);
    }

    fn readOpt(self: *Packet, record: *const Record) Error!void {
        if (self.opt != null) return error.DuplicateOpt;
        if (record.section != .additional) return error.InvalidOpt;
        if (self.bytes[record.owner] != 0) return error.InvalidOpt;
        var options: Options = .{ .bytes = self.bytes[record.data_start..record.data_end] };
        var cookie: ?[]const u8 = null;
        while (try options.next()) |option| {
            if (option.code == cookie_option_code) {
                if (cookie != null) return error.InvalidCookie;
                try validateCookie(option.data);
                cookie = option.data;
            }
        }
        self.opt = self.record_count;
    }
};

pub const Option = struct {
    code: u16,
    data: []const u8,
};

pub const Options = struct {
    bytes: []const u8,
    cursor: usize = 0,

    pub fn next(self: *Options) Error!?Option {
        if (self.cursor == self.bytes.len) return null;
        const fields = take(self.bytes, &self.cursor, option_header_bytes) catch
            return error.InvalidOption;
        const bytes = take(self.bytes, &self.cursor, integer(u16, fields[2..4])) catch
            return error.InvalidOption;
        return .{ .code = integer(u16, fields[0..2]), .data = bytes };
    }
};

pub fn validateCookie(bytes: []const u8) Error!void {
    // RFC 7873 §4: eight client bytes, optionally eight to 32 server bytes.
    if (bytes.len == cookie_client_bytes) return;
    if (bytes.len < cookie_client_bytes + cookie_server_bytes_min) return error.InvalidCookie;
    if (bytes.len > cookie_bytes_max) return error.InvalidCookie;
}

pub const Malformed = union(enum) {
    drop,
    formerr: Header,
};

pub const Query = union(enum) {
    accepted,
    drop,
    reply: Header,
};

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
        header.bits = (header.bits & (opcode_mask | request_flags_mask)) |
            Flag.mask(&.{.response}) | @intFromEnum(Rcode.notimp);
        header.counts = @splat(0);
        return .{ .reply = header };
    }
    if (target.header.counts[0] != 1) return .{ .reply = malformed(bytes).formerr };
    if (target.header.has(.response)) return .{ .reply = malformed(bytes).formerr };
    return .accepted;
}

pub fn malformed(bytes: []const u8) Malformed {
    var header = Header.decode(bytes) catch return .drop;
    header.bits = (header.bits & (opcode_mask | Flag.mask(&.{.recursion_desired}))) |
        Flag.mask(&.{.response}) | @intFromEnum(Rcode.formerr);
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
    if (bytes.len < frame_prefix_bytes) return null;
    const length: usize = integer(u16, bytes[0..frame_prefix_bytes]);
    if (length < header_bytes) return error.Truncated;
    if (bytes.len < length + frame_prefix_bytes) return null;
    return .{
        .message = bytes[frame_prefix_bytes..][0..length],
        .consumed = length + frame_prefix_bytes,
    };
}

pub fn framePrefix(target: []u8, length: usize) Error!void {
    if (length > message_bytes_max) return error.MessageTooLarge;
    if (length < header_bytes) return error.Truncated;
    if (target.len < frame_prefix_bytes) return error.NoSpace;
    put(u16, target[0..frame_prefix_bytes], @intCast(length));
}

comptime {
    if (builtin.is_test) _ = WireTestsExtra;
}

const WireTestsExtra = struct {
    const testing = std.testing;

    // SPEC §3.9: non-QUERY gets NOTIMP and CH is not rejected by the codec.
    test "query disposition separates NOTIMP FORMERR drop and CH" {
        var builder: fixture.Builder = undefined;
        builder.init();
        builder.header.bits = 0x0100;
        builder.question("\x01x\x00", 16, 3);
        var packet: wire.Packet = undefined;
        try testing.expectEqual(.accepted, wire.query(&packet, try builder.finish()));
        builder.header.bits |= 2 << 11;
        const reply = wire.query(&packet, try builder.finish()).reply;
        try testing.expectEqual(4, reply.bits & 15);
        try testing.expectEqual(2, reply.opcode());
        try testing.expect(reply.has(.response));
        try testing.expectEqual(.drop, wire.query(&packet, builder.bytes[0..11]));
        try testing.expectEqual(1, wire.query(&packet, builder.bytes[0..12]).reply.bits & 15);
    }

    // RFC 1035 §4.1.4: the dictionary cannot encode offsets beyond 14 bits.
    test "names after compression offset limit never wrap" {
        var builder: fixture.Builder = undefined;
        builder.init();
        const data: [16370]u8 = @splat(42);
        builder.record(&.{0}, 65400, .answer, &data);
        builder.record("\x01x\x07example\x00", 65400, .answer, &.{});
        builder.record("\x01x\x07example\x00", 65400, .answer, &.{});
        var packet: wire.Packet = undefined;
        try packet.parse(try builder.finish());
        var workspace: wire.rewrite.Workspace = undefined;
        var output: [65535]u8 = undefined;
        const result = try workspace.rewrite(&packet, &output, &.{});
        try testing.expectEqualSlices(u8, packet.bytes, result);
        var decoded: wire.Packet = undefined;
        try decoded.parse(result);
    }

    // SPEC §3.9 and RFC 1035 §4.1.4: large valid packets stay compressed and lossless.
    test "shared long names do not require an expanded message buffer" {
        var name: wire.Name = undefined;
        try fixture.maxName(&name);
        var builder: fixture.Builder = undefined;
        builder.init();
        builder.question(name.wire(), 65400, 1);
        for (0..5000) |_| builder.record("\xc0\x0c", 65400, .answer, &.{});
        var packet: wire.Packet = undefined;
        try packet.parse(try builder.finish());
        try testing.expectEqual(60271, packet.bytes.len);
        var workspace: wire.rewrite.Workspace = undefined;
        var output: [65535]u8 = undefined;
        const result = try workspace.rewrite(&packet, &output, &.{});
        try testing.expectEqualSlices(u8, packet.bytes, result);
    }

    // SPEC §3.7: TTL rewrites do not mutate packet names or OPT metadata.
    test "record views support safe TTL rewrite without changing source bytes" {
        var builder: fixture.Builder = undefined;
        builder.init();
        builder.question("\x01x\x00", 1, 1);
        builder.record("\xc0\x0c", 1, .answer, &.{ 127, 0, 0, 1 });
        builder.record(&.{0}, 41, .additional, &.{});
        var packet: wire.Packet = undefined;
        try packet.parse(try builder.finish());
        const original = std.hash.Wyhash.hash(0, packet.bytes);
        packet.records[0].ttl_s = 5;
        var workspace: wire.rewrite.Workspace = undefined;
        var output: [65535]u8 = undefined;
        const result = try workspace.rewrite(&packet, &output, &.{});
        var decoded: wire.Packet = undefined;
        try decoded.parse(result);
        try testing.expectEqual(5, decoded.records[0].ttl_s);
        try testing.expectEqual(30, decoded.records[1].ttl_s);
        try testing.expectEqual(original, std.hash.Wyhash.hash(0, packet.bytes));
    }

    // RFC 1035 §4.1.4: longest legal backward pointer chains terminate without recursion.
    test "long backward pointer chains have bounded traversal" {
        var builder: fixture.Builder = undefined;
        builder.init();
        builder.question("\x00", 1, 1);
        var previous: u16 = 12;
        for (0..2700) |_| {
            const offset: u16 = @intCast(builder.cursor);
            builder.number(u16, 0xc000 | previous);
            builder.number(u16, 1);
            builder.number(u16, 1);
            builder.header.counts[0] += 1;
            previous = offset;
        }
        var packet: wire.Packet = undefined;
        try packet.parse(try builder.finish());
        var name: wire.Name = undefined;
        try packet.name(&name, previous);
        try testing.expectEqualSlices(u8, &.{0}, name.wire());
    }

    // RFC 6891 §6.2.3 and SPEC §3.9: the UDP payload boundary is inclusive.
    test "UDP exact limit and one byte over retain complete records" {
        var builder: fixture.Builder = undefined;
        const data: [490]u8 = @splat(42);
        var packet: wire.Packet = undefined;
        var decoded: wire.Packet = undefined;
        var workspace: wire.rewrite.Workspace = undefined;
        var output: [65535]u8 = undefined;
        for ([_]usize{ 489, 490 }) |length| {
            builder.init();
            builder.record(&.{0}, 65400, .answer, data[0..length]);
            try packet.parse(try builder.finish());
            const result = try workspace.rewrite(&packet, &output, &.{ .limit = .{ .udp = 512 } });
            try decoded.parse(result);
            try testing.expectEqual(length == 490, decoded.header.has(.truncated));
            try testing.expectEqual(@as(u16, @intFromBool(length == 489)), decoded.record_count);
            try testing.expectEqual(@as(usize, if (length == 489) 512 else 12), result.len);
        }
    }

    // RFC 9619 §4 and RFC 1035 §4.1.1: QUERY needs one question and QR clear.
    test "query classification rejects absent multiple and response questions" {
        var builder: fixture.Builder = undefined;
        builder.init();
        builder.header.bits = 0x0100;
        var packet: wire.Packet = undefined;
        try testing.expectEqual(1, wire.query(&packet, try builder.finish()).reply.bits & 15);
        builder.question("\x01x\x00", 1, 1);
        builder.question("\xc0\x0c", 1, 1);
        try testing.expectEqual(1, wire.query(&packet, try builder.finish()).reply.bits & 15);
        builder.init();
        builder.question("\x01x\x00", 1, 1);
        try testing.expectEqual(1, wire.query(&packet, try builder.finish()).reply.bits & 15);
    }

    // SPEC §1.10–11: storage is fixed, and none of these APIs has an allocator.
    test "codec workspace and metadata stay within explicit storage budgets" {
        try testing.expectEqual(256, @sizeOf(wire.Name));
        try testing.expect(@sizeOf(wire.Packet) <= 128 * 1024);
        try testing.expect(@sizeOf(wire.rewrite.Workspace) <= 64 * 1024);
    }
};

comptime {
    if (builtin.is_test) _ = WireTestsLimits;
}

const WireTestsLimits = struct {
    const testing = std.testing;

    // SPEC §3.9: only a complete header permits FORMERR; short input is dropped.
    test "malformed classification and all truncated prefixes" {
        var builder: fixture.Builder = undefined;
        builder.init();
        builder.question("\x01x\x00", 1, 1);
        builder.record("\xc0\x0c", 6, .authority, "\xc0\x0c\xc0\x0c" ++ "\x00" ** 20);
        const bytes = try builder.finish();
        var packet: wire.Packet = undefined;
        for (0..bytes.len) |length| {
            if (packet.parse(bytes[0..length])) |_| return error.AcceptedTruncatedPacket else |_| {}
            switch (wire.malformed(bytes[0..length])) {
                .drop => try testing.expect(length < 12),
                .formerr => |header| {
                    try testing.expect(length >= 12);
                    try testing.expectEqual(0xabcd, header.id);
                    try testing.expectEqual(1, header.bits & 15);
                    try testing.expect(header.has(.response));
                    try testing.expectEqual([4]u16{ 0, 0, 0, 0 }, header.counts);
                },
            }
        }
        try packet.parse(bytes);
    }

    // RFC 1035 §4.1: widen all hostile counts and lengths before arithmetic.
    test "hostile counts lengths and trailing bytes reject" {
        var packet: wire.Packet = undefined;
        var header: [12]u8 = @splat(255);
        try testing.expectError(error.InvalidCounts, packet.parse(&header));
        var builder: fixture.Builder = undefined;
        builder.init();
        builder.question("\x01x\x00", 1, 1);
        builder.record("\xc0\x0c", 65400, .answer, &.{});
        const bytes = try builder.finish();
        wire.put(u16, bytes[bytes.len - 2 ..], 65535);
        try testing.expectError(error.Truncated, packet.parse(bytes));
        var oversized: [65536]u8 = @splat(0);
        try testing.expectError(error.MessageTooLarge, packet.parse(&oversized));
        header = @splat(0);
        try packet.parse(&header);
        try testing.expectError(error.TrailingData, packet.parse(oversized[0..13]));
        var iterator: wire.Options = .{ .bytes = &.{ 255, 255, 255, 255 } };
        try testing.expectError(error.InvalidOption, iterator.next());
        iterator = .{ .bytes = &.{ 0, 1, 0 } };
        try testing.expectError(error.InvalidOption, iterator.next());
    }

    // RFC 1035 §3.3, §3.4 and RFC 3596 §2.2: typed lengths reject before rewrite.
    test "RDATA bounds include exact names numbers and character strings" {
        const cases = [_]struct { kind: u16, data: []const u8, err: wire.Error }{
            .{ .kind = 1, .data = &.{ 1, 2, 3 }, .err = error.InvalidRecord },
            .{ .kind = 28, .data = &.{0}, .err = error.InvalidRecord },
            .{ .kind = 5, .data = &.{ 0, 0 }, .err = error.InvalidRecord },
            .{ .kind = 6, .data = &.{ 0, 0 }, .err = error.Truncated },
            .{ .kind = 15, .data = &.{ 0, 0, 63 }, .err = error.Truncated },
            .{ .kind = 16, .data = &.{ 255, 0 }, .err = error.Truncated },
            .{ .kind = 13, .data = &.{0}, .err = error.InvalidRecord },
            .{ .kind = 35, .data = &.{ 0, 0, 0, 0, 255 }, .err = error.Truncated },
        };
        for (cases) |case| {
            var builder: fixture.Builder = undefined;
            builder.init();
            builder.record(&.{0}, case.kind, .answer, case.data);
            var packet: wire.Packet = undefined;
            try testing.expectError(case.err, packet.parse(try builder.finish()));
        }
    }

    // RFC 1035 §4.2.2: lengths are unsigned and framing consumes exactly one message.
    test "TCP split coalesced maximum and malformed frame lengths" {
        var bytes: [65539]u8 = @splat(0);
        try wire.framePrefix(&bytes, 65535);
        for ([_]usize{ 0, 1, 2, 12, 65536 }) |length| {
            try testing.expectEqual(null, try wire.frame(bytes[0..length]));
        }
        const complete = (try wire.frame(&bytes)).?;
        try testing.expectEqual(65535, complete.message.len);
        try testing.expectEqual(65537, complete.consumed);
        try testing.expectError(error.MessageTooLarge, wire.framePrefix(&bytes, 65536));
        try testing.expectError(error.NoSpace, wire.framePrefix(bytes[0..1], 12));
        try testing.expectError(error.Truncated, wire.framePrefix(&bytes, 11));
        bytes[0] = 0;
        bytes[1] = 0;
        try testing.expectError(error.Truncated, wire.frame(&bytes));
    }

    // SPEC §3.9, RFC 3597 §4: legacy SRV expansion must not corrupt or truncate TCP.
    test "unrepresentable compliant SRV rewrite returns RewriteTooLarge" {
        var name: wire.Name = undefined;
        try fixture.maxName(&name);
        var builder: fixture.Builder = undefined;
        builder.init();
        builder.question(name.wire(), 33, 1);
        for (0..300) |_| builder.record("\xc0\x0c", 33, .answer, "\x00" ** 6 ++ "\xc0\x0c");
        var packet: wire.Packet = undefined;
        try packet.parse(try builder.finish());
        try testing.expectEqual(6271, packet.bytes.len);
        try testing.expectEqual(82171, 12 + 255 + 4 + 300 * (2 + 10 + 6 + 255));
        var output: [65535]u8 = undefined;
        var workspace: wire.rewrite.Workspace = undefined;
        try testing.expectError(error.RewriteTooLarge, workspace.rewrite(&packet, &output, &.{}));
        const truncated = try workspace.rewrite(&packet, &output, &.{ .limit = .{ .udp = 512 } });
        var decoded: wire.Packet = undefined;
        try decoded.parse(truncated);
        try testing.expect(decoded.header.has(.truncated));
        try testing.expectEqual(0, decoded.record_count);
    }

    // RFC 1035 §2.3.4 and SPEC §9.1: full-size packets do not need expanded storage.
    test "maximum message and maximum record counts are lossless" {
        var builder: fixture.Builder = undefined;
        builder.init();
        const data: [65512]u8 = @splat(0xc0);
        builder.record(&.{0}, 65400, .answer, &data);
        var packet: wire.Packet = undefined;
        try packet.parse(try builder.finish());
        try testing.expectEqual(65535, packet.bytes.len);
        var workspace: wire.rewrite.Workspace = undefined;
        var output: [65535]u8 = undefined;
        try testing.expectEqualSlices(
            u8,
            packet.bytes,
            try workspace.rewrite(&packet, &output, &.{}),
        );
        builder.init();
        for (0..wire.records_max) |_| builder.record(&.{0}, 65400, .answer, &.{});
        try packet.parse(try builder.finish());
        try testing.expectEqual(wire.records_max, packet.record_count);
        try testing.expectEqualSlices(
            u8,
            packet.bytes,
            try workspace.rewrite(&packet, &output, &.{}),
        );
    }
};

comptime {
    if (builtin.is_test) _ = WireTestsTypes;
}

const WireTestsTypes = struct {
    const testing = std.testing;

    // RFC 1035 §4.1.2 and RFC 3597 §3: the codec preserves every 16-bit QTYPE.
    test "record types preserve every assigned unknown and private question code" {
        var input = [_]u8{ 0xab, 0xcd, 0x01, 0x10, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
        var output: [input.len]u8 = undefined;
        var packet: Packet = undefined;
        var encoder: Encoder = undefined;
        var name: Name = undefined;
        for (0..65536) |code| {
            std.mem.writeInt(u16, input[13..15], @intCast(code), .big);
            try packet.parse(&input);
            var cursor: usize = 12;
            const question = try packet.readQuestion(&cursor);
            try testing.expectEqual(@as(u16, @intCast(code)), @intFromEnum(question.kind));
            try packet.name(&name, question.name);
            try encoder.init(&output, &packet.header);
            try encoder.question(&name, question.kind, question.class);
            try testing.expectEqualSlices(u8, &input, try encoder.finish());
        }
    }

    // RFC 1035 §4.1.1: named masks and unknown four-bit response codes retain their wire values.
    test "response flags and all response codes retain exact header bits" {
        try testing.expectEqual(@as(u16, 0x0110), request_flags_mask);
        try testing.expectEqual(@as(u16, 0x8400), Flag.mask(&.{ .response, .authoritative }));
        try testing.expectEqual(@as(u16, 0x8080), Flag.mask(&.{ .response, .recursion_available }));
        for (0..16) |code| {
            const header: Header = .{ .bits = 0xaef0 | @as(u16, @intCast(code)) };
            try testing.expectEqual(@as(u4, @intCast(code)), @intFromEnum(header.rcode()));
        }
    }
};

comptime {
    if (builtin.is_test) _ = FuzzTests;
}

const FuzzTests = struct {
    const testing = std.testing;

    // SPEC §9.3: bounded Smith storage follows the pinned ztls fuzz pattern.
    test "fuzz DNS decoder and safe rewrites" {
        try testing.fuzz({}, fuzzOne, .{ .corpus = &.{ "\x00" ** 12, "\xff" ** 32 } });
    }

    // SPEC §9.3 and RFC 3597 §4: mutate structured packets to reach RDATA and movement.
    test "fuzz structured DNS record relocation" {
        try testing.fuzz({}, fuzzStructured, .{ .corpus = &.{ "", "\x00" ** 32 } });
    }

    // Unexpected outcomes panic: they remain visible with fuzz error tracing disabled.
    fn fuzzOne(_: void, smith: *testing.Smith) error{}!void {
        var storage: [65536]u8 = undefined;
        const length = smith.slice(&storage);
        check(storage[0..length]);
    }

    fn fuzzStructured(_: void, smith: *testing.Smith) error{}!void {
        var mutations: [64]u8 = undefined;
        const length = smith.slice(&mutations);
        var builder: fixture.Builder = undefined;
        builder.init();
        builder.question("\x01x\x07example\x00", 1, 1);
        builder.record("\xc0\x0c", 5, .answer, "\x06target\xc0\x0e");
        builder.record("\xc0\x0c", 15, .answer, "\x00\x0a\xc0\x0c");
        builder.record("\xc0\x0c", 65400, .answer, mutations[0..length]);
        const target: u16 = @intCast(builder.cursor + 14);
        builder.record("\xc0\x0c", 64, .answer, "\x00\x01\x06target\x07example\x00");
        var owner: [2]u8 = undefined;
        wire.put(u16, &owner, 0xc000 | target);
        builder.record(&owner, 1, .answer, &.{ 127, 0, 0, 1 });
        builder.record("\xc0\x0c", 6, .authority, "\xc0\x0c\xc0\x0c" ++ "\x00" ** 20);
        const bytes = builder.finish() catch @panic("fixture header failed");
        if (length >= 3) {
            const offset: usize = wire.integer(u16, mutations[0..2]);
            bytes[offset % bytes.len] = mutations[2];
        }
        check(bytes);
    }

    fn check(bytes: []const u8) void {
        var packet: wire.Packet = undefined;
        packet.parse(bytes) catch {
            _ = wire.malformed(bytes);
            return;
        };
        var order: [wire.records_max]u16 = undefined;
        var start: usize = 0;
        for (0..packet.record_count) |index| {
            order[index] = @intCast(index);
            if (packet.records[index].section != packet.records[start].section) {
                std.mem.reverse(u16, order[start..index]);
                start = index;
            }
        }
        std.mem.reverse(u16, order[start..packet.record_count]);
        var workspace: wire.rewrite.Workspace = undefined;
        var output: [65535]u8 = undefined;
        const result = workspace.rewrite(&packet, &output, &.{
            .order = order[0..packet.record_count],
        }) catch |err| switch (err) {
            error.RewriteTooLarge => return,
            else => @panic(@errorName(err)),
        };
        var decoded: wire.Packet = undefined;
        decoded.parse(result) catch |err| @panic(@errorName(err));
        testing.expectEqual(packet.header, decoded.header) catch @panic("header changed");
        testing.expectEqual(packet.record_count, decoded.record_count) catch
            @panic("record count changed");
        var target: usize = 0;
        for (order[0..packet.record_count]) |index| {
            const record = &packet.records[index];
            const position = if (record.kind == .opt) decoded.opt.? else target;
            equivalent_module.equivalent(
                &packet,
                record,
                &decoded,
                &decoded.records[position],
            ) catch
                @panic("record changed during relocation");
            if (record.kind != .opt) target += 1;
        }
        checkQuestions(&packet, &decoded);
    }

    fn checkQuestions(source: *wire.Packet, target: *wire.Packet) void {
        var source_cursor: usize = 12;
        var target_cursor: usize = 12;
        for (0..source.header.counts[0]) |_| {
            const left = source.readQuestion(&source_cursor) catch
                @panic("source question invalid");
            const right = target.readQuestion(&target_cursor) catch
                @panic("target question invalid");
            var source_name: wire.Name = undefined;
            var target_name: wire.Name = undefined;
            source.name(&source_name, left.name) catch @panic("source name invalid");
            target.name(&target_name, right.name) catch @panic("target name invalid");
            testing.expectEqual(left.kind, right.kind) catch @panic("question type changed");
            testing.expectEqual(left.class, right.class) catch @panic("question class changed");
            testing.expectEqualSlices(u8, source_name.wire(), target_name.wire()) catch
                @panic("question name changed");
        }
    }
};
