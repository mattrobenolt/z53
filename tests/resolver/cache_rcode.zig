const f = @import("cache_fixture.zig");
const testing = f.testing;
const wire = f.wire;

// SPEC §3.9; RFC 6891 §6.1.3: extended errors cannot be represented without client EDNS.
test "cache extended errors without EDNS become uncached local SERVFAIL" {
    for ([_]?f.resolver.config.Cache{ f.zone.cache, null }) |settings| {
        var zone = f.zone;
        zone.cache = settings;
        var fixture: f.Fixture = undefined;
        try fixture.init(testing.allocator, &zone);
        defer fixture.cache.deinit();
        try fixture.client.init("ExAmPlE.", 28, 3);
        for ([_]u8{ 1, 255 }) |extended| {
            for ([_]u16{ 0, 2, 3 }) |low| {
                try fixture.response(0x8520 | low);
                const edns: wire.rewrite.Edns = .{
                    .payload_bytes = 1232,
                    .extended_rcode = extended,
                };
                try wire.rewrite.writeOpt(&fixture.encoder, &edns);
                const result = try fixture.forward(0);
                try testing.expectEqual(.servfail, result.answer.source);
                try testing.expectEqual(.skipped, result.insertion);
                try fixture.client.response.parse(result.answer.bytes);
                try testing.expectEqual(@as(u16, 0x8192), fixture.client.response.header.bits);
                try testing.expectEqual(@as(u16, 0x1234), fixture.client.response.header.id);
                try testing.expectEqualSlices(
                    u16,
                    &.{ 1, 0, 0, 0 },
                    &fixture.client.response.header.counts,
                );
                try testing.expectEqual(null, fixture.client.response.opt);
                var cursor: usize = 12;
                const question = try fixture.client.response.readQuestion(&cursor);
                var name: wire.Name = undefined;
                try fixture.client.response.name(&name, question.name);
                try testing.expectEqualSlices(u8, fixture.client.request.name.wire(), name.wire());
                try testing.expectEqual(@as(u16, 28), question.kind);
                try testing.expectEqual(@as(u16, 3), question.class);
                try testing.expectEqual(null, try fixture.lookup(0));
            }
        }
    }
}

// SPEC §3.7, §3.9: local failure neither replaces existing data nor selects stale data.
test "cache unrepresentable extended errors preserve fresh and stale candidates" {
    for ([_]u16{ 0, 3 }) |rcode| {
        var fixture: f.Fixture = undefined;
        try fixture.init(testing.allocator, &f.zone);
        defer fixture.cache.deinit();
        try fixture.response(0x8500 | rcode);
        if (rcode == 0) {
            try fixture.record(1, .answer, 5, 0);
        } else {
            try fixture.record(6, .authority, 5, 5);
        }
        _ = try fixture.forward(0);
        try fixture.response(0x8500);
        const edns: wire.rewrite.Edns = .{ .payload_bytes = 1232, .extended_rcode = 1 };
        try wire.rewrite.writeOpt(&fixture.encoder, &edns);
        for ([_]u64{ 1, 5 }) |now_s| {
            const result = try fixture.forward(now_s);
            try testing.expectEqual(.servfail, result.answer.source);
            try testing.expectEqual(.skipped, result.insertion);
            try fixture.client.response.parse(result.answer.bytes);
            try testing.expectEqual(@as(u16, 2), fixture.client.response.header.bits & 15);
            try testing.expectEqual(null, fixture.client.response.opt);
            if (now_s == 1) {
                const retained = (try fixture.lookup(now_s)).?;
                try fixture.ttl(&retained, 4);
                try testing.expectEqual(rcode, fixture.client.response.header.bits & 15);
            }
        }
        try testing.expectEqual(null, try fixture.lookup(5));
        const stale = try fixture.failure(5);
        try testing.expectEqual(.stale, stale.answer.source);
        try fixture.ttl(&stale.answer, 30);
        try testing.expectEqual(rcode, fixture.client.response.header.bits & 15);
    }
}

// SPEC §3.9; RFC 6891 §6.1.3; RFC 7873 §4: EDNS retains all RCODE bits and client COOKIE.
test "cache extended errors with EDNS retain RCODE and client envelope" {
    for ([_]?f.resolver.config.Cache{ f.zone.cache, null }) |settings| {
        var zone = f.zone;
        zone.cache = settings;
        var fixture: f.Fixture = undefined;
        try fixture.init(testing.allocator, &zone);
        defer fixture.cache.deinit();
        const cookie = .{ 0, 10, 0, 8 } ++ .{42} ** 8;
        try fixture.client.edns(&cookie);
        for ([_]u8{ 1, 255 }) |extended| {
            for ([_]u16{ 0, 2, 3 }) |low| {
                try fixture.response(0x8500 | low);
                const edns: wire.rewrite.Edns = .{
                    .payload_bytes = 1232,
                    .extended_rcode = extended,
                    .options = &(.{ 0, 10, 0, 8 } ++ .{99} ** 8),
                };
                try wire.rewrite.writeOpt(&fixture.encoder, &edns);
                const result = try fixture.forward(0);
                try testing.expectEqual(.forward, result.answer.source);
                try testing.expectEqual(.skipped, result.insertion);
                try fixture.client.response.parse(result.answer.bytes);
                try testing.expectEqual(low, fixture.client.response.header.bits & 15);
                const opt = fixture.client.response.records[fixture.client.response.opt.?];
                try testing.expectEqual(@as(u32, extended), opt.ttl_s >> 24);
                try testing.expectEqual(@as(u16, 1400), opt.class);
                try testing.expectEqual(@as(u32, 0x8000), opt.ttl_s & 0xffff);
                try testing.expectEqualSlices(
                    u8,
                    &cookie,
                    result.answer.bytes[opt.data_start..opt.data_end],
                );
                try testing.expectEqual(@as(u16, 0x1234), fixture.client.response.header.id);
                try testing.expectEqual(null, try fixture.lookup(0));
            }
        }
    }
}

// SPEC §3.9: short local SERVFAIL output leaves the stale candidate intact.
test "cache extended error local encoding failure preserves stale candidate" {
    var fixture: f.Fixture = undefined;
    try fixture.init(testing.allocator, &f.zone);
    defer fixture.cache.deinit();
    try fixture.response(0x8500);
    try fixture.record(1, .answer, 5, 0);
    _ = try fixture.forward(0);
    try fixture.response(0x8500);
    const edns: wire.rewrite.Edns = .{ .payload_bytes = 1232, .extended_rcode = 1 };
    try wire.rewrite.writeOpt(&fixture.encoder, &edns);
    const bytes = try fixture.encoder.finish();
    for ([_]usize{ 11, 12 }) |length| {
        try testing.expectError(error.NoSpace, fixture.cache.forward(
            &fixture.client.request,
            bytes,
            5,
            &fixture.workspace,
            fixture.client.output[0..length],
        ));
    }
    const stale = try fixture.failure(5);
    try testing.expectEqual(.stale, stale.answer.source);
    try fixture.ttl(&stale.answer, 30);
}
