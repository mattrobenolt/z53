const std = @import("std");
const wire = @import("wire");
const fixture = @import("fixture.zig");
const equivalent = @import("equivalent.zig").equivalent;

// RFC 3597 §4 and RFC 9460 §2.2: later owners may reference uncompressed SVCB targets.
test "SVCB target supplies a later compressed owner without changing opaque RDATA" {
    var builder: fixture.Builder = undefined;
    builder.init();
    builder.question("\x01x\x00", 64, 1);
    builder.record("\xc0\x0c", 64, .answer, "\x00\x01\x06target\x07example\x00");
    builder.record("\xc0\x21", 1, .additional, &.{ 127, 0, 0, 1 });
    const bytes = try builder.finish();
    try std.testing.expectEqual(65, bytes.len);
    var packet: wire.Packet = undefined;
    try packet.parse(bytes);
    try checkRelocation(&packet, "\x06target\x07example\x00", &.{});
}

// RFC 3597 §§3–4: structural provenance works for arbitrary unknown type/class layouts.
test "unknown RDATA owner is encoded afresh even when moved before its source" {
    var builder: fixture.Builder = undefined;
    for ([_]u16{ 65400, 1 }) |kind| {
        builder.init();
        builder.record("\x00", kind, .answer, "\xff\x02\x01x\x07example\x00\xc0\xff");
        wire.put(u16, builder.bytes[15..17], 65200);
        builder.record("\xc0\x19", 1, .answer, &.{ 127, 0, 0, 1 });
        var packet: wire.Packet = undefined;
        try packet.parse(try builder.finish());
        try checkRelocation(&packet, "\x01x\x07example\x00", &.{ 1, 0 });
    }
}

fn checkRelocation(packet: *wire.Packet, expected: []const u8, order: []const u16) !void {
    var name: wire.Name = undefined;
    try packet.name(&name, packet.records[1].owner);
    try std.testing.expectEqualSlices(u8, expected, name.wire());
    var replacement: wire.Name = undefined;
    try replacement.fromText("changed.example.");
    var workspace: wire.rewrite.Workspace = undefined;
    var output: [65535]u8 = undefined;
    const result = try workspace.rewrite(packet, &output, &.{
        .order = order,
        .question = .{ .name = &replacement, .kind = 64, .class = 1 },
    });
    var decoded: wire.Packet = undefined;
    try decoded.parse(result);
    try std.testing.expectEqual(packet.record_count, decoded.record_count);
    for (0..packet.record_count) |position| {
        const source = if (order.len == 0) position else order[position];
        try equivalent(packet, &packet.records[source], &decoded, &decoded.records[position]);
    }
}

// RFC 1035 §§2.3.4, 4.1.4 and RFC 3597 §4: validated suffixes become known boundaries.
test "opaque maximum name publishes labels root and prefixed owner boundaries" {
    var name: wire.Name = undefined;
    try fixture.maxName(&name);
    var builder: fixture.Builder = undefined;
    builder.init();
    builder.record("\x00", 65400, .answer, name.wire());
    builder.record("\xc0\x17", 1, .additional, &.{ 127, 0, 0, 1 });
    builder.record("\x01x\xc0\x57", 1, .additional, &.{ 127, 0, 0, 1 });
    builder.record("\xc1\x15", 1, .additional, &.{ 127, 0, 0, 1 });
    var packet: wire.Packet = undefined;
    try packet.parse(try builder.finish());
    for ([_]usize{ 23, 87, 151, 215, 277 }) |offset| {
        try std.testing.expect(packet.boundaries.isSet(offset));
    }
    try packet.name(&name, packet.records[2].owner);
    try std.testing.expectEqual(193, name.length);
    try std.testing.expectEqualSlices(u8, "\x01x", name.wire()[0..2]);
    try packet.name(&name, packet.records[3].owner);
    try std.testing.expectEqualSlices(u8, "\x00", name.wire());
}

// RFC 1035 §4.1.4: only the target offset, not the whole referenced name, is 14 bits.
test "opaque fallback validates name bytes beyond the pointer offset limit" {
    var builder: fixture.Builder = undefined;
    builder.init();
    const padding: [16349]u8 = @splat(42);
    builder.record("\x00", 65400, .answer, &padding);
    builder.record("\x00", 65400, .answer, "\x01x\x07example\x00");
    pointerRecord(&builder, 16383);
    var packet: wire.Packet = undefined;
    try packet.parse(try builder.finish());
    try std.testing.expectEqual(16383, packet.records[1].data_start);
    var name: wire.Name = undefined;
    try packet.name(&name, packet.records[2].owner);
    try std.testing.expectEqualSlices(u8, "\x01x\x07example\x00", name.wire());
    var workspace: wire.rewrite.Workspace = undefined;
    var output: [65535]u8 = undefined;
    var decoded: wire.Packet = undefined;
    try decoded.parse(try workspace.rewrite(&packet, &output, &.{}));
    for (0..packet.record_count) |index| {
        try equivalent(&packet, &packet.records[index], &decoded, &decoded.records[index]);
    }
}

// RFC 3597 §4 and SPEC §3.9: every name byte must stay in one prior opaque region.
test "opaque fallback rejects label and terminator region escapes" {
    for ([_][]const u8{ "\x03a", "\x01a", "\x01a\x00" }) |data| {
        var builder: fixture.Builder = undefined;
        builder.init();
        builder.record("\x00", 65400, .answer, data);
        builder.record("\x00", 1, .answer, &.{ 127, 0, 0, 1 });
        // The last case targets the RDLENGTH low byte, not the RDATA region.
        const offset: u16 = if (data.len == 3) 22 else 23;
        pointerRecord(&builder, offset);
        var packet: wire.Packet = undefined;
        try std.testing.expectError(error.InvalidPointer, packet.parse(try builder.finish()));
    }
}

// RFC 3597 §4 and SPEC §3.9: unknown RDATA fallback never follows embedded pointers.
test "opaque fallback rejects embedded pointers and publishes no partial boundaries" {
    var builder: fixture.Builder = undefined;
    builder.init();
    builder.question("\x00", 1, 1);
    builder.record("\x00", 65400, .answer, "\x01a\xc0\x0c");
    pointerRecord(&builder, 28);
    var packet: wire.Packet = undefined;
    try std.testing.expectError(error.InvalidPointer, packet.parse(try builder.finish()));
    var boundaries: wire.names.Boundaries = undefined;
    boundaries.init();
    for (28..32) |offset| boundaries.opaque_bytes.set(offset);
    var name: wire.Name = undefined;
    try std.testing.expectError(error.InvalidPointer, wire.names.decode(
        &name,
        builder.bytes[0..builder.cursor],
        32,
        builder.cursor,
        &boundaries,
        .allowed,
    ));
    try std.testing.expect(!boundaries.isSet(28));
    try std.testing.expect(!boundaries.isSet(30));
}

// RFC 1035 §2.3.4: opaque provenance cannot relax the label or expanded-name bounds.
test "opaque fallback rejects oversized labels names and prefixed names" {
    var builder: fixture.Builder = undefined;
    var packet: wire.Packet = undefined;
    builder.init();
    builder.record("\x00", 65400, .answer, "\x40" ++ "a" ** 64 ++ "\x00");
    pointerRecord(&builder, 23);
    try std.testing.expectError(error.LabelTooLong, packet.parse(try builder.finish()));
    var name: wire.Name = undefined;
    try fixture.maxName(&name);
    builder.init();
    builder.record("\x00", 65400, .answer, name.wire());
    builder.record("\x01x\xc0\x17", 1, .additional, &.{ 127, 0, 0, 1 });
    try std.testing.expectError(error.NameTooLong, packet.parse(try builder.finish()));
    var oversized: [257]u8 = undefined;
    @memcpy(oversized[0..2], "\x01x");
    @memcpy(oversized[2..], name.wire());
    builder.init();
    builder.record("\x00", 65400, .answer, &oversized);
    pointerRecord(&builder, 23);
    try std.testing.expectError(error.NameTooLong, packet.parse(try builder.finish()));
}

// RFC 1035 §3.3 and RFC 6891 §6.1.2: known scalar/string/option bytes are not opaque.
test "name shaped known scalar and string fields never supply pointer targets" {
    const Case = struct { kind: u16, data: []const u8, offset: u16 = 0 };
    const cases = [_]Case{
        .{ .kind = 1, .data = "\x01x\x00\x00" },
        .{ .kind = 28, .data = "\x01x\x00" ++ "\x00" ** 13 },
        .{ .kind = 13, .data = "\x03\x01x\x00\x00", .offset = 1 },
        .{ .kind = 16, .data = "\x03\x01x\x00", .offset = 1 },
        .{ .kind = 99, .data = "\x03\x01x\x00", .offset = 1 },
        .{ .kind = 41, .data = "\xfd\xe8\x00\x03\x01x\x00", .offset = 4 },
        .{ .kind = 15, .data = "\x00\x00\x00" },
        .{ .kind = 35, .data = "\x00\x00\x00\x00\x03\x01x\x00\x00\x00\x00", .offset = 5 },
    };
    for (cases) |case| {
        var builder: fixture.Builder = undefined;
        builder.init();
        builder.record("\x00", case.kind, .additional, case.data);
        pointerRecord(&builder, 23 + case.offset);
        var packet: wire.Packet = undefined;
        try std.testing.expectError(error.InvalidPointer, packet.parse(try builder.finish()));
    }
}

fn pointerRecord(builder: *fixture.Builder, offset: u16) void {
    var pointer: [2]u8 = undefined;
    wire.put(u16, &pointer, 0xc000 | offset);
    builder.record(&pointer, 1, .additional, &.{ 127, 0, 0, 1 });
}
