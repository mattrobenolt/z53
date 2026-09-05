const f = @import("cache_fixture.zig");
const testing = f.testing;
const wire = f.wire;

fn alias(fixture: *f.Fixture, owner: []const u8, target: []const u8, kind: u16) !void {
    var name: wire.Name = undefined;
    var destination: wire.Name = undefined;
    try name.fromText(owner);
    try destination.fromText(target);
    const record: wire.Record = .{
        .owner = 0,
        .kind = kind,
        .class = 1,
        .ttl_s = 60,
        .data_start = 0,
        .data_end = 0,
        .section = .answer,
    };
    const offset = try fixture.encoder.beginRecord(&name, &record);
    try fixture.encoder.name(&destination, if (kind == 39) .forbidden else .allowed);
    fixture.encoder.endRecord(offset);
}

fn authority(fixture: *f.Fixture) !void {
    var name: wire.Name = undefined;
    try name.fromText("target.");
    const record: wire.Record = .{
        .owner = 0,
        .kind = 6,
        .class = 1,
        .ttl_s = 60,
        .data_start = 0,
        .data_end = 0,
        .section = .authority,
    };
    const offset = try fixture.encoder.beginRecord(&name, &record);
    try fixture.encoder.name(&name, .allowed);
    try fixture.encoder.name(&name, .allowed);
    for (0..4) |_| try fixture.encoder.number(u32, 0);
    try fixture.encoder.number(u32, 1);
    fixture.encoder.endRecord(offset);
}

// SPEC §3.7; RFC 2308 §2.2; RFC 6672 §3: DNAME redirection is not a terminal A answer.
test "cache DNAME and synthesized CNAME without queried data use denial lifetime" {
    var fixture: f.Fixture = undefined;
    try fixture.init(testing.allocator, &f.zone);
    defer fixture.cache.deinit();
    try fixture.client.init("child.example.", 1, 1);
    try fixture.response(0x8500);
    try alias(&fixture, "example.", "target.", 39);
    try alias(&fixture, "child.example.", "child.target.", 5);
    try authority(&fixture);
    const result = try fixture.forward(0);
    try fixture.ttl(&result.answer, 5);
    try testing.expectEqual(null, fixture.cache.positive.first);
    try testing.expect(fixture.cache.denial.first != null);
    try testing.expectEqual(@as(u16, 2), fixture.client.response.header.counts[1]);
    for (fixture.client.response.records[0..3]) |record| {
        try testing.expectEqual(@as(u32, 5), record.ttl_s);
    }
    const hit = (try fixture.lookup(4)).?;
    try fixture.ttl(&hit, 1);
    try testing.expectEqual(null, try fixture.lookup(5));
    const stale = try fixture.failure(5);
    try testing.expectEqual(.stale, stale.answer.source);
    try fixture.ttl(&stale.answer, 30);
}

// SPEC §3.7; RFC 6672 §3: actual DNAME/CNAME/ANY answers remain positive despite authority SOA.
test "cache queried DNAME CNAME and ANY retain positive lifetime" {
    for ([_]u16{ 39, 5, 255 }) |kind| {
        var fixture: f.Fixture = undefined;
        try fixture.init(testing.allocator, &f.zone);
        defer fixture.cache.deinit();
        try fixture.client.init(if (kind == 5) "child.example." else "example.", kind, 1);
        try fixture.response(0x8500);
        try alias(&fixture, "example.", "target.", 39);
        if (kind == 5) try alias(&fixture, "child.example.", "child.target.", 5);
        try authority(&fixture);
        const result = try fixture.forward(0);
        try fixture.ttl(&result.answer, 60);
        try testing.expect(fixture.cache.positive.first != null);
        try testing.expectEqual(null, fixture.cache.denial.first);
        const hit = (try fixture.lookup(59)).?;
        try fixture.ttl(&hit, 1);
        try testing.expectEqual(null, try fixture.lookup(60));
    }
}
