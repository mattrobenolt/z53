const f = @import("fixture.zig");
const testing = f.testing;
const resolver = f.resolver;
const wire = f.wire;

// SPEC §3.2–3.3; RFC 6761 §6.3: covered names bypass every later stage, for every class.
test "localhost A and AAAA are IN loopbacks with original question class and TTL 30" {
    var fixture: f.Fixture = undefined;
    for ([_][]const u8{ "localhost.", "MiXeD.LocalHOST.", "a.b.localhost." }) |name| {
        for ([_]u16{ 1, 3, 65280 }) |class| {
            for ([_]u16{ 1, 28 }) |kind| {
                try fixture.init(name, kind, class);
                const answer = (try fixture.local()).?;
                try fixture.check(&answer, 1);
                try testing.expectEqual(.rfc6761, answer.source);
                try testing.expect(!answer.source.rotatable());
                const record = fixture.response.records[0];
                try testing.expectEqual(@as(u16, 1), record.class);
                try testing.expectEqual(@as(u32, 30), record.ttl_s);
                const expected: []const u8 = if (kind == 1)
                    &.{ 127, 0, 0, 1 }
                else
                    &(.{0} ** 15 ++ .{1});
                try testing.expectEqualSlices(
                    u8,
                    expected,
                    answer.bytes[record.data_start..record.data_end],
                );
            }
        }
    }
}

// SPEC §3.3; RFC 6761 §6.1, §6.3: only the exact loopback reverse gets a PTR.
test "reverse localhost and covered empty answers" {
    var fixture: f.Fixture = undefined;
    for ([_]u16{ 1, 3, 65280 }) |class| {
        try fixture.init("1.0.0.127.IN-ADDR.ARPA.", 12, class);
        const answer = (try fixture.local()).?;
        try fixture.check(&answer, 1);
        const record = fixture.response.records[0];
        var name: wire.Name = undefined;
        try fixture.response.name(&name, record.data_start);
        var expected: wire.Name = undefined;
        try expected.fromText("localhost.");
        try testing.expect(name.equal(&expected));
        try testing.expectEqual(@as(u16, 1), record.class);
        try testing.expectEqual(@as(u32, 30), record.ttl_s);
    }
    const names = [_][]const u8{
        "localhost.",
        "a.localhost.",
        "0.in-addr.arpa.",
        "127.in-addr.arpa.",
        "255.in-addr.arpa.",
        "a.0.in-addr.arpa.",
        "2.0.0.127.in-addr.arpa.",
        "a.255.in-addr.arpa.",
    };
    for (names) |name| {
        for ([_]u16{ 1, 3, 65280 }) |class| {
            for ([_]u16{ 12, 16, 255 }) |kind| {
                try fixture.init(name, kind, class);
                const answer = (try fixture.local()).?;
                try fixture.check(&answer, 0);
            }
        }
    }
    for ([_][]const u8{
        "1.0.0.127.in-addr.arpa.",
        "x.0.in-addr.arpa.",
        "127.in-addr.arpa.",
        "x.255.in-addr.arpa.",
    }) |name| {
        for ([_]u16{ 1, 28 }) |kind| {
            try fixture.init(name, kind, 1);
            const empty = (try fixture.local()).?;
            try fixture.check(&empty, 0);
        }
    }
}

// SPEC §3.3: suffix matching is label-aware, never a legacy localhost prefix.
test "near misses and binary label dots are not covered" {
    var fixture: f.Fixture = undefined;
    for ([_][]const u8{
        "localhost.example.",
        "notlocalhost.",
        "127.in-addr.arpa.example.",
        "128.in-addr.arpa.",
        "example.",
        ".",
    }) |name| {
        try fixture.init(name, 1, 1);
        try testing.expectEqual(@as(?resolver.Answer, null), try fixture.local());
    }
    try fixture.init("x.localhost.", 1, 1);
    fixture.request.name.length = 13;
    @memcpy(fixture.request.name.bytes[0..13], "\x0bx.localhost\x00");
    try testing.expectEqual(@as(?resolver.Answer, null), try fixture.local());
}

// SPEC §3.4, §3.9; RFC 6891 §6.1.2 and RFC 7873 §4: echo payload and COOKIE only.
test "NODATA any class echoes EDNS and COOKIE but not unknown options" {
    var fixture: f.Fixture = undefined;
    const cookie = [_]u8{ 0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8 };
    for ([_]u16{ 1, 3, 65280 }) |class| {
        try fixture.init("MiXeD.example.", 28, class);
        try fixture.edns(&(cookie ++ .{ 0xfd, 0xe8, 0, 1, 42 }));
        try testing.expectEqual(@as(?resolver.Answer, null), try fixture.local());
        const answer = (try fixture.after(&f.zone, null)).?;
        try fixture.check(&answer, 0);
        try testing.expectEqual(.nodata, answer.source);
        try testing.expect(!answer.source.rotatable());
        const opt = fixture.response.records[fixture.response.opt.?];
        try testing.expectEqual(@as(u16, 1400), opt.class);
        try testing.expectEqual(@as(u32, 0), opt.ttl_s);
        try testing.expectEqualSlices(u8, &cookie, answer.bytes[opt.data_start..opt.data_end]);
    }
    try fixture.init("example.", 28, 1);
    const plain = (try fixture.after(&f.zone, null)).?;
    try fixture.check(&plain, 0);
    try testing.expectEqual(@as(?u16, null), fixture.response.opt);
    try fixture.init("example.", 28, 1);
    try fixture.edns(&.{});
    const edns = (try fixture.after(&f.zone, null)).?;
    try fixture.check(&edns, 0);
    try testing.expectEqual(@as(u16, 1), fixture.response.header.counts[3]);
}

// SPEC §3.2–3.5: RFC6761 wins over AAAA suppression; numeric NODATA is supported.
test "pipeline exposes cache seam and RFC6761 outranks NODATA" {
    var fixture: f.Fixture = undefined;
    try fixture.init("localhost.", 28, 3);
    const local = (try fixture.local()).?;
    try fixture.check(&local, 1);
    try testing.expectEqual(.rfc6761, local.source);
    var zone = f.zone;
    zone.nodata = &.{.{ .number = 65280 }};
    try fixture.init("example.", 65280, 3);
    try testing.expectEqual(@as(?resolver.Answer, null), try fixture.local());
    const answer = (try fixture.after(&zone, null)).?;
    try fixture.check(&answer, 0);
    try testing.expectEqual(.nodata, answer.source);
    try fixture.init("example.", 1, 3);
    try testing.expectEqual(@as(?resolver.Answer, null), try fixture.after(&zone, null));
}

// SPEC §3.9: short output and malformed options fail, never partially succeed.
test "synthetic short buffers and malformed COOKIE are rejected" {
    var fixture: f.Fixture = undefined;
    try fixture.init("localhost.", 1, 1);
    try testing.expectError(
        error.NoSpace,
        resolver.beforeCache(&fixture.request, &fixture.encoder, fixture.output[0..20]),
    );
    try fixture.init("example.", 28, 1);
    try testing.expectError(error.NoSpace, resolver.afterCache(
        &fixture.request,
        &f.zone,
        null,
        &fixture.encoder,
        fixture.output[0..12],
    ));
    try fixture.init("example.", 28, 1);
    try fixture.edns(&.{ 0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8 });
    const opt = fixture.query.records[fixture.query.opt.?];
    wire.put(u16, fixture.input[opt.data_start + 2 ..][0..2], 9);
    switch (wire.query(&fixture.query, fixture.query.bytes)) {
        .reply => |header| try testing.expectEqual(@as(u16, 1), header.bits & 15),
        else => return error.TestExpectedEqual,
    }
}

// SPEC §3.4; RFC 7873 §4: the maximum valid client/server COOKIE fits bounded scratch.
test "NODATA echoes a maximum length server COOKIE" {
    var fixture: f.Fixture = undefined;
    try fixture.init("example.", 28, 1);
    const cookie = .{ 0, 10, 0, 40 } ++ .{0xaa} ** 40;
    try fixture.edns(&cookie);
    const answer = (try fixture.after(&f.zone, null)).?;
    try fixture.check(&answer, 0);
    const opt = fixture.response.records[fixture.response.opt.?];
    try testing.expectEqualSlices(u8, &cookie, answer.bytes[opt.data_start..opt.data_end]);
}
