const std = @import("std");
const wire = @import("wire");
const fixture = @import("fixture.zig");

// RFC 1035 §§4.1.2, 4.1.4: one decode supplies fields and a case-preserving expanded name.
test "question decode publishes names into reusable caller storage" {
    var builder: fixture.Builder = undefined;
    builder.init();
    builder.question("\x03WwW\x07ExAmPlE\x00", 1, 1);
    builder.question("\xc0\x0c", 28, 3);
    var packet: wire.Packet = undefined;
    try packet.parse(try builder.finish());
    var name: wire.Name = undefined;
    try name.fromText("retained.invalid.");
    var cursor: usize = 12;
    const first = try packet.readQuestionInto(&name, &cursor);
    try std.testing.expectEqual(12, first.name);
    try std.testing.expectEqual(1, first.kind);
    try std.testing.expectEqual(1, first.class);
    try std.testing.expectEqual(29, cursor);
    try std.testing.expectEqualSlices(u8, "\x03WwW\x07ExAmPlE\x00", name.wire());
    try name.fromText("another.retained.invalid.");
    const second = try packet.readQuestionInto(&name, &cursor);
    try std.testing.expectEqual(29, second.name);
    try std.testing.expectEqual(28, second.kind);
    try std.testing.expectEqual(3, second.class);
    try std.testing.expectEqual(packet.bytes.len, cursor);
    try std.testing.expectEqualSlices(u8, "\x03WwW\x07ExAmPlE\x00", name.wire());
}

// RFC 1035 §4.1.2: the direct decoder still requires four bytes for type and class.
test "question decode rejects truncated fields and permits clean reuse" {
    var builder: fixture.Builder = undefined;
    builder.init();
    builder.question("\x03www\x00", 1, 1);
    const bytes = try builder.finish();
    var packet: wire.Packet = undefined;
    try packet.parse(bytes);
    packet.bytes = bytes[0 .. bytes.len - 1];
    var name: wire.Name = undefined;
    var cursor: usize = 12;
    try std.testing.expectError(error.Truncated, packet.readQuestionInto(&name, &cursor));
    try packet.parse(bytes);
    cursor = 12;
    const question = try packet.readQuestionInto(&name, &cursor);
    try std.testing.expectEqual(1, question.kind);
    try std.testing.expectEqual(1, question.class);
    try std.testing.expectEqualSlices(u8, "\x03www\x00", name.wire());
}

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
