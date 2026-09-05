const std = @import("std");
const wire = @import("wire");
const fixture = @import("fixture.zig");

const cookie = "\x00\x0a\x00\x08abcdefgh";
const unknown = "\xfd\xe8\x00\x03\xc0\x0c\xff";

// RFC 6891 §6.1 and RFC 7873 §4: preserve options, metadata and client COOKIE.
test "EDNS round trip and client envelope replacement" {
    var bytes: [65535]u8 = undefined;
    var encoder: wire.Encoder = undefined;
    try encoder.init(&bytes, &.{ .id = 123, .bits = 0x8180 });
    var name: wire.Name = undefined;
    try name.fromText("server.example.");
    try encoder.question(&name, 28, 3);
    const edns: wire.rewrite.Edns = .{
        .payload_bytes = 4096,
        .extended_rcode = 1,
        .version = 1,
        .flags = 0x8000,
        .options = cookie ++ unknown,
    };
    try wire.rewrite.writeOpt(&encoder, &edns);
    var packet: wire.Packet = undefined;
    try packet.parse(try encoder.finish());
    var workspace: wire.rewrite.Workspace = undefined;
    var output: [65535]u8 = undefined;
    try std.testing.expectEqualSlices(
        u8,
        packet.bytes,
        try workspace.rewrite(&packet, &output, &.{}),
    );
    const upstream = wire.rewrite.upstreamEdns(&packet);
    try std.testing.expectEqual(1232, upstream.payload_bytes);
    try std.testing.expectEqual(0x8000, upstream.flags);
    try std.testing.expectEqual(0, upstream.version);
    try std.testing.expectEqualSlices(u8, cookie ++ unknown, upstream.options);
    var options: [44]u8 = undefined;
    const client: wire.rewrite.Edns = .{
        .payload_bytes = 1232,
        .options = try wire.rewrite.responseOptions(&packet, &options),
    };
    try std.testing.expectEqualSlices(u8, cookie, client.options);
    try name.fromText("Client.Example.");
    const result = try workspace.rewrite(&packet, &output, &.{
        .id = 456,
        .question = .{ .name = &name, .kind = 1, .class = 3 },
        .opt = .{ .replace = &client },
    });
    var decoded: wire.Packet = undefined;
    try decoded.parse(result);
    try std.testing.expectEqual(456, decoded.header.id);
    try std.testing.expectEqual(1232, decoded.records[decoded.opt.?].class);
    try std.testing.expectEqual(0, decoded.records[decoded.opt.?].ttl_s);
    var cursor: usize = 12;
    const question = try decoded.readQuestion(&cursor);
    try std.testing.expectEqual(3, question.class);
    var restored: wire.Name = undefined;
    try decoded.name(&restored, question.name);
    try std.testing.expectEqualSlices(u8, name.wire(), restored.wire());
    try decoded.parse(try workspace.rewrite(&packet, &output, &.{ .opt = .omit }));
    try std.testing.expectEqual(null, decoded.opt);
}

// RFC 6891 §6.1.1 and RFC 7873 §4: invalid or repeated OPT/COOKIE is FORMERR.
test "OPT owner section duplicates and COOKIE lengths reject" {
    for ([_]usize{ 0, 7, 9, 15, 41 }) |length| {
        const data: [41]u8 = @splat(0);
        try std.testing.expectError(error.InvalidCookie, wire.validateCookie(data[0..length]));
    }
    for ([_]usize{ 8, 16, 40 }) |length| {
        const data: [40]u8 = @splat(0);
        try wire.validateCookie(data[0..length]);
    }
    var builder: fixture.Builder = undefined;
    var packet: wire.Packet = undefined;
    builder.init();
    builder.record(&.{0}, 41, .answer, &.{});
    try std.testing.expectError(error.InvalidOpt, packet.parse(try builder.finish()));
    builder.init();
    builder.record("\x01x\x00", 41, .additional, &.{});
    try std.testing.expectError(error.InvalidOpt, packet.parse(try builder.finish()));
    builder.init();
    builder.record(&.{0}, 41, .additional, cookie ++ cookie);
    try std.testing.expectError(error.InvalidCookie, packet.parse(try builder.finish()));
    builder.init();
    builder.record(&.{0}, 41, .additional, &.{});
    builder.record(&.{0}, 41, .additional, &.{});
    try std.testing.expectError(error.DuplicateOpt, packet.parse(try builder.finish()));
    builder.init();
    builder.record(&.{0}, 41, .additional, &.{ 0, 10, 0, 8 });
    try std.testing.expectError(error.InvalidOption, packet.parse(try builder.finish()));
}

// RFC 2181 §9 and SPEC §3.9: keep whole RRsets, the question and required OPT.
test "UDP truncation removes interleaved partial RRsets and reserves OPT" {
    var builder: fixture.Builder = undefined;
    builder.init();
    builder.question("\x01x\x00", 65400, 1);
    const data: [160]u8 = @splat(42);
    builder.record("\xc0\x0c", 65400, .answer, &data);
    builder.record("\x01y\x00", 65400, .answer, &data);
    builder.record("\xc0\x0c", 65400, .answer, &data);
    var packet: wire.Packet = undefined;
    try packet.parse(try builder.finish());
    var workspace: wire.rewrite.Workspace = undefined;
    var output: [65535]u8 = undefined;
    const opt: wire.rewrite.Edns = .{ .payload_bytes = 512, .options = cookie };
    const result = try workspace.rewrite(&packet, &output, &.{
        .limit = .{ .udp = 512 },
        .opt = .{ .replace = &opt },
    });
    try std.testing.expect(result.len <= 512);
    var decoded: wire.Packet = undefined;
    try decoded.parse(result);
    try std.testing.expect(decoded.header.has(.truncated));
    try std.testing.expectEqual(0, decoded.header.counts[1]);
    try std.testing.expectEqual(1, decoded.header.counts[0]);
    try std.testing.expectEqual(1, decoded.header.counts[3]);
    const complete = try workspace.rewrite(&packet, &output, &.{});
    try decoded.parse(complete);
    try std.testing.expectEqual(3, decoded.header.counts[1]);
    try std.testing.expect(!decoded.header.has(.truncated));
}

// SPEC §3.9: order changes cannot duplicate records or cross DNS sections.
test "invalid permutations and small output fail explicitly" {
    var builder: fixture.Builder = undefined;
    builder.init();
    builder.record(&.{0}, 65400, .answer, &.{});
    builder.record(&.{0}, 65400, .additional, &.{});
    var packet: wire.Packet = undefined;
    try packet.parse(try builder.finish());
    var output: [65535]u8 = undefined;
    var workspace: wire.rewrite.Workspace = undefined;
    for ([_][]const u16{ &.{0}, &.{ 0, 0 }, &.{ 0, 2 }, &.{ 1, 0 } }) |order| {
        try std.testing.expectError(
            error.InvalidOrder,
            workspace.rewrite(&packet, &output, &.{ .order = order }),
        );
    }
    try std.testing.expectError(error.NoSpace, workspace.rewrite(&packet, output[0..11], &.{}));
    try std.testing.expectError(error.NoSpace, workspace.rewrite(&packet, output[0..12], &.{}));
}
