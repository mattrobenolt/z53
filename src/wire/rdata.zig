const builtin = @import("builtin");
const std = @import("std");
const equivalent_module = @import("../testing/equivalent.zig");
const equivalent = equivalent_module.equivalent;
const fixture = @import("../testing/wire.zig");
const ArrayBuffer = @import("../array_buffer.zig").ArrayBuffer;
const wire = @import("../wire.zig");
const names = wire.names;

pub const Range = struct {
    start: u16,
    end: u16,
};

pub const NamePart = struct {
    offset: u16,
    compression: names.Compression,
};

pub const Part = union(enum) {
    bytes: Range,
    name: NamePart,
};

const parts_max = 7;
const soa_integers_bytes = 5 * @sizeOf(u32);
const signature_fields_bytes = 18;
const srv_fields_bytes = 3 * @sizeOf(u16);
const naptr_fields_bytes = 2 * @sizeOf(u16);

pub const Parts = struct {
    items: ArrayBuffer(Part, parts_max),

    fn add(self: *Parts, part: Part) void {
        // Every supported layout fits within parts_max; NAPTR is the largest at five parts.
        self.items.appendAssumeCapacity(part);
    }
};

/// RFC 3597 §4 lists all historical compression-capable layouts.
/// Legacy non-1035 names decode compression but never emit it.
pub fn parse(target: *Parts, packet: *wire.Packet, record: *const wire.Record) wire.Error!void {
    target.items.clear();
    var cursor: usize = record.data_start;
    const end: usize = record.data_end;
    switch (record.kind) {
        .ns, .md, .mf, .cname, .mb, .mg, .mr, .ptr => {
            try name(target, packet, &cursor, end, .allowed, .allowed);
        },
        .soa => {
            try name(target, packet, &cursor, end, .allowed, .allowed);
            try name(target, packet, &cursor, end, .allowed, .allowed);
            try bytes(target, packet.bytes, &cursor, end, soa_integers_bytes);
        },
        .minfo, .rp => {
            const output: names.Compression = if (record.kind == .minfo) .allowed else .forbidden;
            try name(target, packet, &cursor, end, .allowed, output);
            try name(target, packet, &cursor, end, .allowed, output);
        },
        .mx, .afsdb, .rt, .kx => {
            try bytes(target, packet.bytes, &cursor, end, 2);
            const input: names.Compression = if (record.kind == .kx) .forbidden else .allowed;
            const output: names.Compression = if (record.kind == .mx) .allowed else .forbidden;
            try name(target, packet, &cursor, end, input, output);
        },
        .sig, .rrsig => try signature(target, packet, &cursor, end, record.kind),
        .px => {
            try bytes(target, packet.bytes, &cursor, end, 2);
            try name(target, packet, &cursor, end, .allowed, .forbidden);
            try name(target, packet, &cursor, end, .allowed, .forbidden);
        },
        .nxt, .nsec => {
            const input: names.Compression = if (record.kind == .nxt) .allowed else .forbidden;
            try name(target, packet, &cursor, end, input, .forbidden);
            try bytes(target, packet.bytes, &cursor, end, end - cursor);
        },
        .srv => {
            try bytes(target, packet.bytes, &cursor, end, srv_fields_bytes);
            try name(target, packet, &cursor, end, .allowed, .forbidden);
        },
        .naptr => try naptr(target, packet, &cursor, end),
        .nsap_ptr => try name(target, packet, &cursor, end, .allowed, .forbidden),
        .dname => try name(target, packet, &cursor, end, .forbidden, .forbidden),
        else => try opaqueData(target, packet, record, &cursor, end),
    }
    if (cursor != end) return error.InvalidRecord;
}

fn name(
    parts: *Parts,
    packet: *wire.Packet,
    cursor: *usize,
    end: usize,
    input: names.Compression,
    output: names.Compression,
) wire.Error!void {
    var expanded: names.Name = undefined;
    const offset: u16 = @intCast(cursor.*);
    cursor.* = try names.decode(&expanded, packet.bytes, cursor.*, end, &packet.boundaries, input);
    parts.add(.{ .name = .{ .offset = offset, .compression = output } });
}

fn bytes(
    parts: *Parts,
    packet: []const u8,
    cursor: *usize,
    end: usize,
    length: usize,
) wire.Error!void {
    const start: u16 = @intCast(cursor.*);
    _ = try wire.take(packet[0..end], cursor, length);
    parts.add(.{ .bytes = .{ .start = start, .end = @intCast(cursor.*) } });
}

fn signature(
    parts: *Parts,
    packet: *wire.Packet,
    cursor: *usize,
    end: usize,
    kind: wire.RecordType,
) wire.Error!void {
    try bytes(parts, packet.bytes, cursor, end, signature_fields_bytes);
    const input: names.Compression = if (kind == .sig) .allowed else .forbidden;
    try name(parts, packet, cursor, end, input, .forbidden);
    try bytes(parts, packet.bytes, cursor, end, end - cursor.*);
}

fn naptr(parts: *Parts, packet: *wire.Packet, cursor: *usize, end: usize) wire.Error!void {
    try bytes(parts, packet.bytes, cursor, end, naptr_fields_bytes);
    for (0..3) |_| {
        if (cursor.* >= end) return error.Truncated;
        try bytes(parts, packet.bytes, cursor, end, @as(usize, packet.bytes[cursor.*]) + 1);
    }
    try name(parts, packet, cursor, end, .allowed, .forbidden);
}

fn opaqueData(
    parts: *Parts,
    packet: *wire.Packet,
    record: *const wire.Record,
    cursor: *usize,
    end: usize,
) wire.Error!void {
    const length = end - cursor.*;
    if (record.class == wire.class_in) {
        switch (record.kind) {
            .a => if (length != 4) return error.InvalidRecord,
            .aaaa => if (length != 16) return error.InvalidRecord,
            else => {},
        }
    }
    // Character strings are bounded independently of the surrounding RDLENGTH.
    switch (record.kind) {
        .hinfo => {
            try strings(packet.bytes[cursor.*..end], 2);
        },
        .txt, .spf => {
            if (length == 0) return error.InvalidRecord;
            try strings(packet.bytes[cursor.*..end], null);
        },
        else => {},
    }
    if (unknownLayout(record)) {
        // Headers separate RDATA ranges, so adjacent set bits stay in one record.
        for (cursor.*..end) |offset| packet.boundaries.opaque_bytes.set(offset);
    }
    try bytes(parts, packet.bytes, cursor, end, length);
}

fn unknownLayout(record: *const wire.Record) bool {
    return switch (record.kind) {
        .null_record, .hinfo, .txt, .opt, .spf => false,
        .a, .wks, .aaaa => record.class != wire.class_in,
        else => true,
    };
}

fn strings(data: []const u8, expected: ?u16) wire.Error!void {
    var cursor: usize = 0;
    var count: u16 = 0;
    while (cursor < data.len) : (count += 1) {
        const length = data[cursor];
        cursor += 1;
        _ = try wire.take(data, &cursor, length);
    }
    if (expected) |wanted| {
        if (count != wanted) return error.InvalidRecord;
    }
}

comptime {
    if (builtin.is_test) _ = WireTestsRecords;
}

const WireTestsRecords = struct {
    const testing = std.testing;

    // RFC 1035 §4.1.1–4.1.3: all header bits, questions and sections round trip.
    test "header questions and all record sections round trip" {
        const header: wire.Header = .{ .id = 65535, .bits = 0xffff, .counts = .{ 1, 2, 3, 4 } };
        var header_output: [12]u8 = undefined;
        try header.encode(&header_output);
        try testing.expectEqual(header, try wire.Header.decode(&header_output));
        var builder: fixture.Builder = undefined;
        builder.init();
        builder.question("\x01x\x00", 1, 3);
        for ([_]wire.Section{ .answer, .authority, .additional }) |section| {
            builder.record("\xc0\x0c", 1, section, &.{ 127, 0, 0, 1 });
        }
        var packet: wire.Packet = undefined;
        try packet.parse(try builder.finish());
        var output: [65535]u8 = undefined;
        var workspace: wire.rewrite.Workspace = undefined;
        const result = try workspace.rewrite(&packet, &output, &.{});
        try testing.expectEqualSlices(u8, packet.bytes, result);
        var decoded: wire.Packet = undefined;
        try decoded.parse(result);
        try testing.expectEqual(3, decoded.record_count);
    }

    // RFC 3597 §4, RFC 1035 §3.3, RFC 1348 §2: relocate every legacy name layout.
    test "all compression capable RDATA layouts survive moving records" {
        const kinds = [_]u16{
            2,
            3,
            4,
            5,
            6,
            7,
            8,
            9,
            12,
            14,
            15,
            17,
            18,
            21,
            23,
            24,
            26,
            30,
            33,
            35,
        };
        for (kinds) |kind| try movedRecord(kind);
    }

    fn movedRecord(kind: u16) !void {
        var builder: fixture.Builder = undefined;
        builder.init();
        builder.question("\x01x\x00", 1, 1);
        const target_offset: u16 = @intCast(builder.cursor + 12);
        builder.record("\xc0\x0c", 5, .answer, "\x06target\x04test\x00");
        var pointer: [2]u8 = undefined;
        wire.put(u16, &pointer, 0xc000 | target_offset);
        var data: fixture.Builder = undefined;
        data.init();
        legacyData(&data, kind, &pointer);
        builder.record(&pointer, kind, .answer, data.bytes[12..data.cursor]);
        var packet: wire.Packet = undefined;
        try packet.parse(try builder.finish());
        var output: [65535]u8 = undefined;
        var workspace: wire.rewrite.Workspace = undefined;
        const result = try workspace.rewrite(&packet, &output, &.{ .order = &.{ 1, 0 } });
        var decoded: wire.Packet = undefined;
        try decoded.parse(result);
        try equivalent(&packet, &packet.records[1], &decoded, &decoded.records[0]);
        try equivalent(&packet, &packet.records[0], &decoded, &decoded.records[1]);
    }

    fn legacyData(data: *fixture.Builder, kind: u16, pointer: *const [2]u8) void {
        switch (kind) {
            15, 18, 21, 26 => data.append(&.{ 0, 10 }),
            24 => data.append(&(@as([18]u8, @splat(0)))),
            33 => data.append(&.{ 0, 0, 0, 0, 0, 53 }),
            35 => data.append(&.{ 0, 0, 0, 0, 1, 's', 0, 0 }),
            else => {},
        }
        data.append(pointer);
        switch (kind) {
            6, 14, 17, 26 => data.append(pointer),
            else => {},
        }
        switch (kind) {
            6 => data.append(&(@as([20]u8, @splat(0)))),
            24, 30 => data.append(&.{ 0xc0, 0xff }),
            else => {},
        }
    }

    // RFC 3597 §3: opaque RDATA containing pointer-like bytes is never interpreted.
    test "unknown and modern opaque records preserve binary RDATA" {
        for ([_]u16{ 65400, 48, 50, 52, 64, 65 }) |kind| {
            var builder: fixture.Builder = undefined;
            builder.init();
            builder.question("\x01x\x00", 1, 1);
            builder.record("\xc0\x0c", kind, .answer, &.{ 0xc0, 12, 0xff, 0, 255 });
            var packet: wire.Packet = undefined;
            try packet.parse(try builder.finish());
            var output: [65535]u8 = undefined;
            var workspace: wire.rewrite.Workspace = undefined;
            const result = try workspace.rewrite(&packet, &output, &.{});
            try testing.expectEqualSlices(u8, packet.bytes, result);
        }
    }

    // RFC 3597 §4, RFC 4034 §3 and §4, RFC 6672 §2.1: modern names forbid compression.
    test "modern known name restrictions reject pointers" {
        for ([_]u16{ 36, 39, 46, 47 }) |kind| {
            var builder: fixture.Builder = undefined;
            builder.init();
            builder.question("\x01x\x00", 1, 1);
            var data: fixture.Builder = undefined;
            data.init();
            if (kind == 36) data.append(&.{ 0, 10 });
            if (kind == 46) data.append(&(@as([18]u8, @splat(0))));
            data.append("\xc0\x0c");
            builder.record("\xc0\x0c", kind, .answer, data.bytes[12..data.cursor]);
            var packet: wire.Packet = undefined;
            try testing.expectError(error.CompressionForbidden, packet.parse(try builder.finish()));
        }
    }
};
