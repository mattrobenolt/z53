const std = @import("std");
const wire = @import("wire");
const fixture = @import("fixture.zig");
const equivalent = @import("equivalent.zig").equivalent;

// RFC 1035 §4.1.1–4.1.3: all header bits, questions and sections round trip.
test "header questions and all record sections round trip" {
    const header: wire.Header = .{ .id = 65535, .bits = 0xffff, .counts = .{ 1, 2, 3, 4 } };
    var bytes: [12]u8 = undefined;
    try header.encode(&bytes);
    try std.testing.expectEqual(header, try wire.Header.decode(&bytes));
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
    try std.testing.expectEqualSlices(u8, packet.bytes, result);
    var decoded: wire.Packet = undefined;
    try decoded.parse(result);
    try std.testing.expectEqual(3, decoded.record_count);
}

// RFC 3597 §4, RFC 1035 §3.3, RFC 1348 §2: relocate every legacy name layout.
test "all compression capable RDATA layouts survive moving records" {
    const kinds = [_]u16{ 2, 3, 4, 5, 6, 7, 8, 9, 12, 14, 15, 17, 18, 21, 23, 24, 26, 30, 33, 35 };
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
        try std.testing.expectEqualSlices(u8, packet.bytes, result);
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
        try std.testing.expectError(error.CompressionForbidden, packet.parse(try builder.finish()));
    }
}
