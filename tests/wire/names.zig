const std = @import("std");
const wire = @import("wire");
const fixture = @import("fixture.zig");

// RFC 1035 §2.3.4 and SPEC §9.1: 63-byte labels and 255-byte names are inclusive.
test "name exact bounds and hostile label encodings" {
    var name: wire.Name = undefined;
    try fixture.maxName(&name);
    try name.validate();
    try std.testing.expectEqual(255, name.length);
    var builder: fixture.Builder = undefined;
    builder.init();
    builder.question(name.wire(), 1, 1);
    var packet: wire.Packet = undefined;
    try packet.parse(try builder.finish());
    for ([_]u8{ 64, 128, 191 }) |invalid| {
        builder.bytes[12] = invalid;
        try std.testing.expectError(error.LabelTooLong, packet.parse(try builder.finish()));
    }
    try std.testing.expectError(error.NameTooLong, name.append(&.{0}));
    var long: [256]u8 = @splat('a');
    for ([_]usize{ 0, 64, 128 }) |offset| long[offset] = 63;
    long[192] = 62;
    long[255] = 0;
    builder.init();
    builder.question(&long, 1, 1);
    try std.testing.expectError(error.NameTooLong, packet.parse(try builder.finish()));
    try std.testing.expectError(error.LabelTooLong, name.fromText("a" ** 64));
    try std.testing.expectError(error.InvalidName, name.fromText("a..b"));
    try std.testing.expectError(error.InvalidName, name.fromText(""));
}

// RFC 1035 §4.1.4: suffix and pointer chains resolve only prior label boundaries.
test "compressed names decode suffixes and pointer chains" {
    var builder: fixture.Builder = undefined;
    builder.init();
    builder.question("\x03www\x07example\x00", 1, 3);
    const second: u16 = @intCast(builder.cursor);
    builder.question("\x03api\xc0\x10", 28, 1);
    builder.number(u16, 0xc000 | second);
    builder.number(u16, 15);
    builder.number(u16, 1);
    builder.header.counts[0] += 1;
    var packet: wire.Packet = undefined;
    try packet.parse(try builder.finish());
    var name: wire.Name = undefined;
    try packet.name(&name, @intCast(second + 10));
    try std.testing.expectEqualSlices(u8, "\x03api\x07example\x00", name.wire());
}

// RFC 1035 §4.1.4 and SPEC §3.9: corrupt pointers never become names.
test "pointer targets reject header interior forward self and cycles" {
    var builder: fixture.Builder = undefined;
    builder.init();
    builder.question("\x03www\x00", 1, 1);
    const offset = builder.cursor;
    builder.question("\xc0\x0c", 1, 1);
    var packet: wire.Packet = undefined;
    for ([_]u16{ 0, 13, @intCast(offset), @intCast(offset + 2), 0x3fff }) |pointer| {
        wire.put(u16, builder.bytes[offset..][0..2], 0xc000 | pointer);
        try std.testing.expectError(error.InvalidPointer, packet.parse(try builder.finish()));
    }
    builder.init();
    builder.question("\x01a\xc0\x0c", 1, 1);
    try std.testing.expectError(error.Truncated, packet.parse(try builder.finish()));
}

// RFC 1035 §2.3.3: names contain arbitrary octets, not dot-delimited text.
test "binary name representation does not alias label separators" {
    var source: wire.Name = .{ .length = 0 };
    try source.append("\x03a.b\x00");
    var target: wire.Name = undefined;
    try target.fromText("a.b.");
    try std.testing.expect(!source.equal(&target));
    try source.fromText("WWW.Example.");
    try target.fromText("www.example");
    try std.testing.expect(source.equal(&target));
    try source.fromText(".");
    try std.testing.expectEqualSlices(u8, &.{0}, source.wire());
}
