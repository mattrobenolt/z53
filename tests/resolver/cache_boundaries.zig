const std = @import("std");
const f = @import("cache_fixture.zig");
const testing = f.testing;
const wire = f.wire;

// SPEC §3.7; RFC 2308 §5: default denial cap, stale TTL 30, and fresh answer replacement.
test "denial default maximum stale and positive replacement" {
    var fixture: f.Fixture = undefined;
    try fixture.init(testing.allocator, &f.zone);
    defer fixture.cache.deinit();
    try fixture.response(0x8503);
    try fixture.record(6, .authority, 5000, 4000);
    const denied = try fixture.forward(0);
    try fixture.ttl(&denied.answer, 1800);
    const stale = try fixture.failure(1800);
    try testing.expectEqual(.stale, stale.answer.source);
    try fixture.ttl(&stale.answer, 30);
    try testing.expectEqual(@as(u16, 3), fixture.client.response.header.bits & 15);
    try fixture.response(0x8500);
    try fixture.record(1, .answer, 60, 0);
    _ = try fixture.forward(1801);
    const hit = (try fixture.lookup(1802)).?;
    try fixture.ttl(&hit, 59);
    try testing.expectEqual(@as(u16, 0), fixture.client.response.header.bits & 15);
    for (fixture.cache.denial.entries) |entry| try testing.expectEqual(null, entry.bytes);
}

// SPEC §3.7, §3.9; RFC 7873 §4: DO-clear EDNS shares plain data, not another client's COOKIE.
test "cache plain client omits stored EDNS and binary name dots cannot alias" {
    var fixture: f.Fixture = undefined;
    try fixture.init(testing.allocator, &f.zone);
    defer fixture.cache.deinit();
    try fixture.client.init("a.example.", 1, 3);
    const cookie = .{ 0, 10, 0, 40 } ++ .{42} ** 40;
    try fixture.client.edns(&cookie);
    fixture.client.query.records[fixture.client.query.opt.?].ttl_s = 0;
    try fixture.response(0x8500);
    try fixture.record(1, .answer, 60, 0);
    const edns: wire.rewrite.Edns = .{ .payload_bytes = 1232, .options = &cookie };
    try wire.rewrite.writeOpt(&fixture.encoder, &edns);
    _ = try fixture.forward(0);
    try fixture.client.init("A.EXAMPLE.", 1, 3);
    const hit = (try fixture.lookup(0)).?;
    try fixture.ttl(&hit, 60);
    try testing.expectEqual(null, fixture.client.response.opt);
    try testing.expectEqual(@as(u16, 3), fixture.client.response.records[0].class);
    fixture.client.request.name.length = 11;
    @memcpy(fixture.client.request.name.bytes[0..11], "\x09a.example\x00");
    try testing.expectEqual(null, try fixture.lookup(0));
}

// SPEC §3.7: positive and denial capacity are separate, including SERVFAIL in the denial bank.
test "denial churn cannot evict a full positive bank" {
    var fixture: f.Fixture = undefined;
    try fixture.init(testing.allocator, &f.zone);
    defer fixture.cache.deinit();
    for ([_][]const u8{ "one.", "two." }) |name| {
        try fixture.client.init(name, 1, 1);
        try fixture.response(0x8500);
        try fixture.record(1, .answer, 60, 0);
        _ = try fixture.forward(0);
    }
    for ([_][]const u8{ "denied-one.", "denied-two.", "denied-three." }) |name| {
        try fixture.client.init(name, 1, 1);
        _ = try fixture.failure(0);
    }
    for ([_][]const u8{ "one.", "two." }) |name| {
        try fixture.client.init(name, 1, 1);
        try testing.expect((try fixture.lookup(0)) != null);
    }
    try fixture.client.init("denied-one.", 1, 1);
    try testing.expectEqual(null, try fixture.lookup(0));
}

// SPEC §3.7: TTL and clock arithmetic widen instead of wrapping at u32/u64 limits.
test "maximum TTL aging does not wrap and zero positive TTL can expire immediately" {
    var fixture: f.Fixture = undefined;
    var zone = f.zone;
    zone.cache.?.max_ttl_s = std.math.maxInt(u32);
    try fixture.init(testing.allocator, &zone);
    defer fixture.cache.deinit();
    try fixture.response(0x8500);
    try fixture.record(1, .answer, std.math.maxInt(u32), 0);
    _ = try fixture.forward(0);
    const hit = (try fixture.lookup(std.math.maxInt(u32) - 1)).?;
    try fixture.ttl(&hit, 1);
    try testing.expectEqual(null, try fixture.lookup(std.math.maxInt(u32)));
    const stale = try fixture.failure(@as(u64, std.math.maxInt(u32)) + 1);
    try fixture.ttl(&stale.answer, 30);
    fixture.cache.settings.?.min_ttl_s = 0;
    try fixture.response(0x8500);
    try fixture.record(1, .answer, 0, 0);
    const result = try fixture.forward(std.math.maxInt(u64));
    try fixture.ttl(&result.answer, 0);
    try testing.expectEqual(null, try fixture.lookup(std.math.maxInt(u64)));
    try testing.expectEqual(.stale, (try fixture.failure(std.math.maxInt(u64))).answer.source);
}

// SPEC §3.7; RFC 2308 §2.2: an actual answer to CNAME/ANY is positive, not a CNAME-chain denial.
test "queried CNAME and ANY remain positive with authority SOA" {
    var fixture: f.Fixture = undefined;
    try fixture.init(testing.allocator, &f.zone);
    defer fixture.cache.deinit();
    for ([_]u16{ 5, 255 }) |kind| {
        try fixture.client.init("example.", kind, 1);
        try fixture.response(0x8500);
        try fixture.record(5, .answer, 60, 0);
        try fixture.record(6, .authority, 60, 1);
        const result = try fixture.forward(0);
        try fixture.ttl(&result.answer, 60);
        const hit = (try fixture.lookup(59)).?;
        try fixture.ttl(&hit, 1);
    }
}
