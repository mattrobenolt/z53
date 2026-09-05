const std = @import("std");
const wire = @import("wire");
const fixture = @import("fixture.zig");

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
            .drop => try std.testing.expect(length < 12),
            .formerr => |header| {
                try std.testing.expect(length >= 12);
                try std.testing.expectEqual(0xabcd, header.id);
                try std.testing.expectEqual(1, header.bits & 15);
                try std.testing.expect(header.has(.response));
                try std.testing.expectEqual([4]u16{ 0, 0, 0, 0 }, header.counts);
            },
        }
    }
    try packet.parse(bytes);
}

// RFC 1035 §4.1: widen all hostile counts and lengths before arithmetic.
test "hostile counts lengths and trailing bytes reject" {
    var packet: wire.Packet = undefined;
    var header: [12]u8 = @splat(255);
    try std.testing.expectError(error.InvalidCounts, packet.parse(&header));
    var builder: fixture.Builder = undefined;
    builder.init();
    builder.question("\x01x\x00", 1, 1);
    builder.record("\xc0\x0c", 65400, .answer, &.{});
    const bytes = try builder.finish();
    wire.put(u16, bytes[bytes.len - 2 ..], 65535);
    try std.testing.expectError(error.Truncated, packet.parse(bytes));
    var oversized: [65536]u8 = @splat(0);
    try std.testing.expectError(error.MessageTooLarge, packet.parse(&oversized));
    header = @splat(0);
    try packet.parse(&header);
    try std.testing.expectError(error.TrailingData, packet.parse(oversized[0..13]));
    var iterator: wire.Options = .{ .bytes = &.{ 255, 255, 255, 255 } };
    try std.testing.expectError(error.InvalidOption, iterator.next());
    iterator = .{ .bytes = &.{ 0, 1, 0 } };
    try std.testing.expectError(error.InvalidOption, iterator.next());
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
        try std.testing.expectError(case.err, packet.parse(try builder.finish()));
    }
}

// RFC 1035 §4.2.2: lengths are unsigned and framing consumes exactly one message.
test "TCP split coalesced maximum and malformed frame lengths" {
    var bytes: [65539]u8 = @splat(0);
    try wire.framePrefix(&bytes, 65535);
    for ([_]usize{ 0, 1, 2, 12, 65536 }) |length| {
        try std.testing.expectEqual(null, try wire.frame(bytes[0..length]));
    }
    const complete = (try wire.frame(&bytes)).?;
    try std.testing.expectEqual(65535, complete.message.len);
    try std.testing.expectEqual(65537, complete.consumed);
    try std.testing.expectError(error.MessageTooLarge, wire.framePrefix(&bytes, 65536));
    try std.testing.expectError(error.NoSpace, wire.framePrefix(bytes[0..1], 12));
    try std.testing.expectError(error.Truncated, wire.framePrefix(&bytes, 11));
    bytes[0] = 0;
    bytes[1] = 0;
    try std.testing.expectError(error.Truncated, wire.frame(&bytes));
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
    try std.testing.expectEqual(6271, packet.bytes.len);
    try std.testing.expectEqual(82171, 12 + 255 + 4 + 300 * (2 + 10 + 6 + 255));
    var output: [65535]u8 = undefined;
    var workspace: wire.rewrite.Workspace = undefined;
    try std.testing.expectError(error.RewriteTooLarge, workspace.rewrite(&packet, &output, &.{}));
    const truncated = try workspace.rewrite(&packet, &output, &.{ .limit = .{ .udp = 512 } });
    var decoded: wire.Packet = undefined;
    try decoded.parse(truncated);
    try std.testing.expect(decoded.header.has(.truncated));
    try std.testing.expectEqual(0, decoded.record_count);
}

// RFC 1035 §2.3.4 and SPEC §9.1: full-size packets do not need expanded storage.
test "maximum message and maximum record counts are lossless" {
    var builder: fixture.Builder = undefined;
    builder.init();
    const data: [65512]u8 = @splat(0xc0);
    builder.record(&.{0}, 65400, .answer, &data);
    var packet: wire.Packet = undefined;
    try packet.parse(try builder.finish());
    try std.testing.expectEqual(65535, packet.bytes.len);
    var workspace: wire.rewrite.Workspace = undefined;
    var output: [65535]u8 = undefined;
    try std.testing.expectEqualSlices(
        u8,
        packet.bytes,
        try workspace.rewrite(&packet, &output, &.{}),
    );
    builder.init();
    for (0..wire.records_max) |_| builder.record(&.{0}, 65400, .answer, &.{});
    try packet.parse(try builder.finish());
    try std.testing.expectEqual(wire.records_max, packet.record_count);
    try std.testing.expectEqualSlices(
        u8,
        packet.bytes,
        try workspace.rewrite(&packet, &output, &.{}),
    );
}
