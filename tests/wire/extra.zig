const std = @import("std");
const wire = @import("wire");
const fixture = @import("fixture.zig");

// SPEC §3.9: non-QUERY gets NOTIMP and CH is not rejected by the codec.
test "query disposition separates NOTIMP FORMERR drop and CH" {
    var builder: fixture.Builder = undefined;
    builder.init();
    builder.header.bits = 0x0100;
    builder.question("\x01x\x00", 16, 3);
    var packet: wire.Packet = undefined;
    try std.testing.expectEqual(.accepted, wire.query(&packet, try builder.finish()));
    builder.header.bits |= 2 << 11;
    const reply = wire.query(&packet, try builder.finish()).reply;
    try std.testing.expectEqual(4, reply.bits & 15);
    try std.testing.expectEqual(2, reply.opcode());
    try std.testing.expect(reply.has(.response));
    try std.testing.expectEqual(.drop, wire.query(&packet, builder.bytes[0..11]));
    try std.testing.expectEqual(1, wire.query(&packet, builder.bytes[0..12]).reply.bits & 15);
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
    try std.testing.expectEqualSlices(u8, packet.bytes, result);
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
    try std.testing.expectEqual(60271, packet.bytes.len);
    var workspace: wire.rewrite.Workspace = undefined;
    var output: [65535]u8 = undefined;
    const result = try workspace.rewrite(&packet, &output, &.{});
    try std.testing.expectEqualSlices(u8, packet.bytes, result);
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
    try std.testing.expectEqual(5, decoded.records[0].ttl_s);
    try std.testing.expectEqual(30, decoded.records[1].ttl_s);
    try std.testing.expectEqual(original, std.hash.Wyhash.hash(0, packet.bytes));
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
    try std.testing.expectEqualSlices(u8, &.{0}, name.wire());
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
        try std.testing.expectEqual(length == 490, decoded.header.has(.truncated));
        try std.testing.expectEqual(@as(u16, @intFromBool(length == 489)), decoded.record_count);
        try std.testing.expectEqual(@as(usize, if (length == 489) 512 else 12), result.len);
    }
}

// RFC 9619 §4 and RFC 1035 §4.1.1: QUERY needs one question and QR clear.
test "query classification rejects absent multiple and response questions" {
    var builder: fixture.Builder = undefined;
    builder.init();
    builder.header.bits = 0x0100;
    var packet: wire.Packet = undefined;
    try std.testing.expectEqual(1, wire.query(&packet, try builder.finish()).reply.bits & 15);
    builder.question("\x01x\x00", 1, 1);
    builder.question("\xc0\x0c", 1, 1);
    try std.testing.expectEqual(1, wire.query(&packet, try builder.finish()).reply.bits & 15);
    builder.init();
    builder.question("\x01x\x00", 1, 1);
    try std.testing.expectEqual(1, wire.query(&packet, try builder.finish()).reply.bits & 15);
}

// SPEC §1.10–11: storage is fixed, and none of these APIs has an allocator.
test "codec workspace and metadata stay within explicit storage budgets" {
    try std.testing.expectEqual(256, @sizeOf(wire.Name));
    try std.testing.expect(@sizeOf(wire.Packet) <= 128 * 1024);
    try std.testing.expect(@sizeOf(wire.rewrite.Workspace) <= 64 * 1024);
}
