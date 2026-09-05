const std = @import("std");
const f = @import("cache_fixture.zig");
const testing = f.testing;
const wire = f.wire;

// SPEC §3.7; RFC 1035 §4.1.3: clamp every non-OPT TTL, age from insertion, expire at minimum.
test "cache positive TTL clamps and deterministic aging preserve upstream flags" {
    var fixture: f.Fixture = undefined;
    try fixture.init(testing.allocator, &f.zone);
    defer fixture.cache.deinit();
    try fixture.response(0x8520);
    try fixture.record(1, .answer, 0, 0);
    try fixture.record(1, .authority, 4000, 0);
    try fixture.record(1, .additional, 20, 0);
    const result = try fixture.forward(100);
    try testing.expectEqual(.stored, result.insertion);
    try fixture.ttl(&result.answer, 5);
    try testing.expectEqual(@as(u32, 3600), fixture.client.response.records[1].ttl_s);
    try testing.expectEqual(@as(u16, 0x85a0), fixture.client.response.header.bits);
    const hit = (try fixture.lookup(104)).?;
    try testing.expectEqual(.cache, hit.source);
    try fixture.ttl(&hit, 1);
    try testing.expectEqual(@as(u32, 3596), fixture.client.response.records[1].ttl_s);
    try testing.expectEqual(@as(u32, 16), fixture.client.response.records[2].ttl_s);
    try testing.expectEqual(null, try fixture.lookup(105));
    const stale = try fixture.failure(105);
    try fixture.ttl(&stale.answer, 30);
    for (fixture.client.response.records[0..3]) |record| {
        try testing.expectEqual(@as(u32, 30), record.ttl_s);
    }
}

// SPEC §3.7; RFC 2308 §3, §5: NXDOMAIN/NODATA use min(SOA TTL, MINIMUM), fixed floor five.
test "cache denial clamps ignore positive minimum and share positive maximum cap" {
    var fixture: f.Fixture = undefined;
    var zone = f.zone;
    zone.cache = .{ .capacity = 2, .min_ttl_s = 20, .max_ttl_s = 30, .neg_max_ttl_s = 25 };
    try fixture.init(testing.allocator, &zone);
    defer fixture.cache.deinit();
    for ([_]u16{ 0x8500, 0x8503 }) |bits| {
        const cases = [_][3]u32{
            .{ 0, 100, 5 }, .{ 100, 2, 5 }, .{ 10, 100, 10 }, .{ 100, 100, 25 },
        };
        for (cases) |values| {
            try fixture.response(bits);
            try fixture.record(6, .authority, values[0], values[1]);
            const result = try fixture.forward(0);
            try testing.expectEqual(.stored, result.insertion);
            try fixture.ttl(&result.answer, values[2]);
            const hit = (try fixture.lookup(values[2] - 1)).?;
            try fixture.ttl(&hit, 1);
            try testing.expectEqual(null, try fixture.lookup(values[2]));
        }
    }
    fixture.cache.settings.?.neg_max_ttl_s = 1800;
    try fixture.response(0x8503);
    try fixture.record(5, .answer, 100, 0);
    try fixture.record(6, .authority, 100, 100);
    const capped = try fixture.forward(0);
    try fixture.ttl(&capped.answer, 30);
    try testing.expectEqual(@as(u32, 30), fixture.workspace.packet.records[1].ttl_s);
    try fixture.response(0x8500);
    try fixture.record(5, .answer, 100, 0);
    try fixture.record(6, .authority, 100, 100);
    _ = try fixture.forward(0);
    const entry = &fixture.cache.denial.entries[fixture.cache.denial.first.?];
    try testing.expectEqual(@as(u32, 30), entry.lifetime_s);
}

// SPEC §3.7; RFC 6891 §6.1.3: class/type/framed case-insensitive name/DO key excludes client ID.
test "cache key dimensions and per-client question EDNS COOKIE rewriting" {
    var fixture: f.Fixture = undefined;
    try fixture.init(testing.allocator, &f.zone);
    defer fixture.cache.deinit();
    const first_cookie = .{ 0, 10, 0, 8 } ++ .{1} ** 8;
    const next_cookie = .{ 0, 10, 0, 8 } ++ .{2} ** 8;
    try fixture.client.edns(&first_cookie);
    try fixture.response(0x8500);
    try fixture.record(1, .answer, 60, 0);
    const edns: wire.rewrite.Edns = .{
        .payload_bytes = 1232,
        .flags = 0x8000,
        .options = &first_cookie,
    };
    try wire.rewrite.writeOpt(&fixture.encoder, &edns);
    _ = try fixture.forward(0);
    const stored = fixture.cache.positive.entries[fixture.cache.positive.first.?].bytes.?;
    try fixture.client.response.parse(stored);
    try testing.expectEqual(null, fixture.client.response.opt);
    try testing.expectEqual(@as(u16, 0), fixture.client.response.header.id);
    try fixture.client.init("EXAMPLE.", 1, 1);
    try testing.expectEqual(null, try fixture.lookup(1));
    try fixture.client.edns(&(next_cookie ++ .{ 0xfd, 0xe8, 0, 0 }));
    fixture.client.query.header.id = 42;
    fixture.client.query.records[fixture.client.query.opt.?].class = 4096;
    const hit = (try fixture.lookup(1)).?;
    try fixture.ttl(&hit, 59);
    const response = &fixture.client.response;
    try testing.expectEqual(@as(u16, 42), response.header.id);
    var cursor: usize = 12;
    const question = try response.readQuestion(&cursor);
    var name: wire.Name = undefined;
    try response.name(&name, question.name);
    try testing.expectEqualSlices(u8, fixture.client.request.name.wire(), name.wire());
    const opt = response.records[response.opt.?];
    try testing.expectEqual(@as(u16, 4096), opt.class);
    try testing.expectEqual(@as(u32, 0x8000), opt.ttl_s);
    try testing.expectEqualSlices(u8, &next_cookie, hit.bytes[opt.data_start..opt.data_end]);
    fixture.client.request.class = 3;
    try testing.expectEqual(null, try fixture.lookup(1));
    fixture.client.request.class = 1;
    fixture.client.request.kind = 28;
    try testing.expectEqual(null, try fixture.lookup(1));
    fixture.client.request.kind = 1;
    try fixture.client.request.name.fromText("other.");
    try testing.expectEqual(null, try fixture.lookup(1));
}

// SPEC §3.7; RFC 8767 §5: only exhausted transports unlock stale, with an exclusive grace end.
test "stale precedes terminal SERVFAIL without replacing or extending its candidate" {
    var fixture: f.Fixture = undefined;
    try fixture.init(testing.allocator, &f.zone);
    defer fixture.cache.deinit();
    try fixture.response(0x8500);
    try fixture.record(1, .answer, 5, 0);
    _ = try fixture.forward(std.math.maxInt(u64) - 20);
    for ([_]u64{ 5, 14 }) |elapsed| {
        const now_s = std.math.maxInt(u64) - 20 + elapsed;
        try testing.expectEqual(null, try fixture.lookup(now_s));
        const result = try fixture.failure(now_s);
        try testing.expectEqual(.stale, result.answer.source);
        try testing.expectEqual(.skipped, result.insertion);
        try fixture.ttl(&result.answer, 30);
    }
    const result = try fixture.failure(std.math.maxInt(u64) - 5);
    try testing.expectEqual(.servfail, result.answer.source);
    try testing.expectEqual(.stored, result.insertion);
    const hit = (try fixture.lookup(std.math.maxInt(u64) - 1)).?;
    try fixture.client.response.parse(hit.bytes);
    try testing.expectEqual(@as(u16, 2), fixture.client.response.header.bits & 15);
    try testing.expectEqual(null, try fixture.lookup(std.math.maxInt(u64)));
    const again = try fixture.failure(std.math.maxInt(u64));
    try testing.expectEqual(.servfail, again.answer.source);
}

// SPEC §3.6–3.7: upstream SERVFAIL is an answer, not transport exhaustion or stale eligibility.
test "upstream SERVFAIL caches five seconds and stale disabled means terminal failure" {
    var fixture: f.Fixture = undefined;
    var zone = f.zone;
    zone.serve_stale_s = 0;
    try fixture.init(testing.allocator, &zone);
    defer fixture.cache.deinit();
    try fixture.response(0x8500);
    try fixture.record(1, .answer, 5, 0);
    _ = try fixture.forward(0);
    const terminal = try fixture.failure(5);
    try testing.expectEqual(.servfail, terminal.answer.source);
    try testing.expectEqual(null, try fixture.lookup(10));
    try fixture.response(0x8502);
    _ = try fixture.forward(10);
    try testing.expect((try fixture.lookup(14)) != null);
    try testing.expectEqual(null, try fixture.lookup(15));
    fixture.cache.grace_s = 100;
    const failure = try fixture.failure(15);
    try testing.expectEqual(.servfail, failure.answer.source);
}

// SPEC §3.7: independent LRUs refresh hit recency; replacements change banks.
test "cache LRU eviction is independent for positive and denial entries" {
    var fixture: f.Fixture = undefined;
    try fixture.init(testing.allocator, &f.zone);
    defer fixture.cache.deinit();
    for ([_]u16{ 0x8500, 0x8503 }) |bits| {
        for ([_][]const u8{ "one.", "two.", "three." }, 0..) |name, index| {
            if (index == 2) {
                try fixture.client.init("one.", 1, 1);
                try testing.expect((try fixture.lookup(0)) != null);
            }
            try fixture.client.init(name, 1, 1);
            try fixture.response(bits);
            if (bits == 0x8500) {
                try fixture.record(1, .answer, 60, 0);
            } else try fixture.record(6, .authority, 60, 60);
            _ = try fixture.forward(0);
        }
        try fixture.client.init("two.", 1, 1);
        try testing.expectEqual(null, try fixture.lookup(0));
        try fixture.client.init("one.", 1, 1);
        try testing.expect((try fixture.lookup(0)) != null);
    }
    try testing.expectEqual(@as(usize, 2), fixture.cache.positive.entries.len);
    try testing.expectEqual(@as(usize, 2), fixture.cache.denial.entries.len);
    // The denial replacement removed the matching positive entries, rather than shadowing them.
    for (fixture.cache.positive.entries) |entry| try testing.expectEqual(null, entry.bytes);
}

// SPEC §3.7; RFC 2308 §5: incomplete and uncacheable errors cannot evict an existing answer.
test "cache skips truncation unsupported rcodes missing SOA and disabled zones" {
    var fixture: f.Fixture = undefined;
    try fixture.init(testing.allocator, &f.zone);
    defer fixture.cache.deinit();
    for ([_]u16{ 0x8300, 0x8105, 0x8103, 0x8100, 0x0100 }) |bits| {
        try fixture.response(bits);
        const result = try fixture.forward(0);
        try testing.expectEqual(.skipped, result.insertion);
        try testing.expectEqual(null, try fixture.lookup(0));
    }
    try fixture.response(0x8100);
    try fixture.record(1, .answer, 60, 0);
    const edns: wire.rewrite.Edns = .{ .payload_bytes = 1232, .extended_rcode = 1 };
    try wire.rewrite.writeOpt(&fixture.encoder, &edns);
    try testing.expectEqual(.skipped, (try fixture.forward(0)).insertion);
    fixture.cache.deinit();
    var zone = f.zone;
    zone.cache = null;
    try fixture.cache.init(testing.allocator, &zone);
    try fixture.response(0x8500);
    try fixture.record(1, .answer, 0, 0);
    const result = try fixture.forward(0);
    try testing.expectEqual(.skipped, result.insertion);
    try fixture.ttl(&result.answer, 0);
    try testing.expectEqual(null, try fixture.lookup(0));
}
