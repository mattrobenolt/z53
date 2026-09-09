//! Synchronous pipeline seams. The runtime routes first, then calls beforeCache;
//! only its miss permits cache lookup, and only a cache miss permits afterCache.
//! Output must not overlap the borrowed request packet or encoder workspace.
const builtin = @import("builtin");
const test_fixture = @import("testing/resolver.zig");
const std = @import("std");
const assert = std.debug.assert;

pub const cache = @import("cache.zig");
pub const config = @import("config.zig");
pub const hosts = @import("hosts.zig");
pub const rotation = @import("rotation.zig");
pub const Source = rotation.Source;
pub const wire = @import("wire.zig");

pub const Request = struct {
    packet: *const wire.Packet,
    name: wire.Name,
    kind: wire.RecordType,
    class: u16,

    /// Accept only packets already admitted by wire.query.
    pub fn init(self: *Request, packet: *wire.Packet) wire.Error!void {
        assert(packet.header.counts[0] == 1);
        assert(packet.header.opcode() == 0);
        assert(!packet.header.has(.response));
        var cursor: usize = wire.header_bytes;
        const question = try packet.readQuestion(&cursor);
        self.packet = packet;
        self.kind = question.kind;
        self.class = question.class;
        try packet.name(&self.name, question.name);
    }
};

pub const Answer = struct {
    bytes: []const u8,
    source: Source,
};

const Local = enum { loopback, reverse, empty };

/// A returned answer bypasses cache, NODATA, hosts, forward, and rotation.
/// null means the runtime must try its per-zone cache next.
pub fn beforeCache(
    request: *const Request,
    encoder: *wire.Encoder,
    output: []u8,
) wire.Error!?Answer {
    const local = covered(&request.name) orelse return null;
    try start(request, encoder, output);
    switch (local) {
        .loopback => switch (request.kind) {
            .a => try address(encoder, &request.name, .a, &.{ 127, 0, 0, 1 }),
            .aaaa => try address(encoder, &request.name, .aaaa, &(.{0} ** 15 ++ .{1})),
            else => {},
        },
        .reverse => {
            if (request.kind == .ptr) {
                const offset = try record(encoder, &request.name, .ptr, 30);
                var localhost: wire.Name = undefined;
                localhost.fromText("localhost.") catch unreachable;
                try encoder.name(&localhost, .allowed);
                encoder.endRecord(offset);
            }
        },
        .empty => {},
    }
    const answer = try finish(request, encoder, .rfc6761);
    return answer;
}

/// Invoke only after beforeCache and the cache both miss. null means forward.
/// NODATA and hosts answers never enter the cache. Only hosts may rotate.
pub fn afterCache(
    request: *const Request,
    zone: *const config.Zone,
    table: ?*const hosts.Table,
    encoder: *wire.Encoder,
    output: []u8,
) wire.Error!?Answer {
    return afterCacheInner(request, zone, table, encoder, output) catch |err| {
        if (err == error.NoSpace) {
            if (output.len >= wire.message_bytes_max) return error.RewriteTooLarge;
        }
        return err;
    };
}

fn afterCacheInner(
    request: *const Request,
    zone: *const config.Zone,
    table: ?*const hosts.Table,
    encoder: *wire.Encoder,
    output: []u8,
) wire.Error!?Answer {
    for (zone.nodata) |kind| {
        if (kind.code() != request.kind) continue;
        try start(request, encoder, output);
        const answer = try finish(request, encoder, .nodata);
        return answer;
    }
    const settings = zone.hosts orelse return null;
    if (request.class != wire.class_in) return null;
    const snapshot = table orelse return null;
    var count: u16 = 0;
    for (snapshot.entries()) |*entry| {
        if (!entry.matches(&request.name, request.kind)) continue;
        if (count == 0) try start(request, encoder, output);
        const offset = try record(encoder, &request.name, request.kind, settings.ttl);
        try entry.write(encoder, request.kind);
        encoder.endRecord(offset);
        count += 1;
    }
    if (count == 0) return null;
    const answer = try finish(request, encoder, .hosts);
    return answer;
}

fn start(request: *const Request, encoder: *wire.Encoder, output: []u8) wire.Error!void {
    // Echo RD/CD only. Synthetic data is authoritative, never authenticated or recursive.
    const header: wire.Header = .{
        .id = request.packet.header.id,
        .bits = (request.packet.header.bits & wire.request_flags_mask) |
            wire.Flag.mask(&.{ .response, .authoritative }),
    };
    try encoder.init(output, &header);
    try encoder.question(&request.name, request.kind, request.class);
}

fn finish(request: *const Request, encoder: *wire.Encoder, source: Source) wire.Error!Answer {
    var cookie: [wire.cookie_option_bytes_max]u8 = undefined;
    if (request.packet.opt) |index| {
        const options = try wire.rewrite.responseOptions(request.packet, &cookie);
        const edns: wire.rewrite.Edns = .{
            .payload_bytes = request.packet.records[index].class,
            .options = options,
        };
        try wire.rewrite.writeOpt(encoder, &edns);
    }
    return .{ .bytes = try encoder.finish(), .source = source };
}

fn record(
    encoder: *wire.Encoder,
    name: *const wire.Name,
    kind: wire.RecordType,
    ttl_s: u32,
) wire.Error!usize {
    const value: wire.Record = .{
        .owner = 0,
        .kind = kind,
        .class = wire.class_in,
        .ttl_s = ttl_s,
        .data_start = 0,
        .data_end = 0,
        .section = .answer,
    };
    return encoder.beginRecord(name, &value);
}

fn address(
    encoder: *wire.Encoder,
    name: *const wire.Name,
    kind: wire.RecordType,
    bytes: []const u8,
) wire.Error!void {
    const offset = try record(encoder, name, kind, 30);
    try encoder.bytes(bytes);
    encoder.endRecord(offset);
}

fn covered(name: *const wire.Name) ?Local {
    var suffix: wire.Name = undefined;
    suffix.fromText("1.0.0.127.in-addr.arpa.") catch unreachable;
    if (name.eql(&suffix)) return .reverse;
    const zones = .{ "localhost.", "0.in-addr.arpa.", "127.in-addr.arpa.", "255.in-addr.arpa." };
    inline for (zones, 0..) |zone, index| {
        suffix.fromText(zone) catch unreachable;
        var offset: usize = 0;
        while (offset < name.length) {
            if (std.ascii.eqlIgnoreCase(name.wire()[offset..], suffix.wire())) {
                return if (index == 0) .loopback else .empty;
            }
            offset += @as(usize, name.bytes[offset]) + 1;
        }
    }
    return null;
}

comptime {
    if (builtin.is_test) {
        _ = ResolverTestsSynthetic;
        _ = cache;
    }
}

const ResolverTestsSynthetic = struct {
    const testing = test_fixture.testing;
    const resolver = test_fixture.resolver;

    // SPEC §3.2–3.3; RFC 6761 §6.3: covered names bypass every later stage, for every class.
    test "localhost A and AAAA are IN loopbacks with original question class and TTL 30" {
        var fixture: test_fixture.Fixture = undefined;
        for ([_][]const u8{ "localhost.", "MiXeD.LocalHOST.", "a.b.localhost." }) |name| {
            for ([_]u16{ 1, 3, 65280 }) |class| {
                for ([_]u16{ 1, 28 }) |kind| {
                    try fixture.init(name, kind, class);
                    const answer = (try fixture.local()).?;
                    try fixture.check(&answer, 1);
                    try testing.expectEqual(.rfc6761, answer.source);
                    try testing.expect(!answer.source.rotatable());
                    const answer_record = fixture.response.records[0];
                    try testing.expectEqual(@as(u16, 1), answer_record.class);
                    try testing.expectEqual(@as(u32, 30), answer_record.ttl_s);
                    const expected: []const u8 = if (kind == 1)
                        &.{ 127, 0, 0, 1 }
                    else
                        &(.{0} ** 15 ++ .{1});
                    try testing.expectEqualSlices(
                        u8,
                        expected,
                        answer.bytes[answer_record.data_start..answer_record.data_end],
                    );
                }
            }
        }
    }

    // SPEC §3.3; RFC 6761 §6.1, §6.3: only the exact loopback reverse gets a PTR.
    test "reverse localhost and covered empty answers" {
        var fixture: test_fixture.Fixture = undefined;
        for ([_]u16{ 1, 3, 65280 }) |class| {
            try fixture.init("1.0.0.127.IN-ADDR.ARPA.", 12, class);
            const answer = (try fixture.local()).?;
            try fixture.check(&answer, 1);
            const answer_record = fixture.response.records[0];
            var name: wire.Name = undefined;
            try fixture.response.name(&name, answer_record.data_start);
            var expected: wire.Name = undefined;
            try expected.fromText("localhost.");
            try testing.expect(name.eql(&expected));
            try testing.expectEqual(@as(u16, 1), answer_record.class);
            try testing.expectEqual(@as(u32, 30), answer_record.ttl_s);
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
        var fixture: test_fixture.Fixture = undefined;
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
        var fixture: test_fixture.Fixture = undefined;
        const cookie = [_]u8{ 0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8 };
        for ([_]u16{ 1, 3, 65280 }) |class| {
            try fixture.init("MiXeD.example.", 28, class);
            try fixture.edns(&(cookie ++ .{ 0xfd, 0xe8, 0, 1, 42 }));
            try testing.expectEqual(@as(?resolver.Answer, null), try fixture.local());
            const answer = (try fixture.after(&test_fixture.zone, null)).?;
            try fixture.check(&answer, 0);
            try testing.expectEqual(.nodata, answer.source);
            try testing.expect(!answer.source.rotatable());
            const opt = fixture.response.records[fixture.response.opt.?];
            try testing.expectEqual(@as(u16, 1400), opt.class);
            try testing.expectEqual(@as(u32, 0), opt.ttl_s);
            try testing.expectEqualSlices(u8, &cookie, answer.bytes[opt.data_start..opt.data_end]);
        }
        try fixture.init("example.", 28, 1);
        const plain = (try fixture.after(&test_fixture.zone, null)).?;
        try fixture.check(&plain, 0);
        try testing.expectEqual(@as(?u16, null), fixture.response.opt);
        try fixture.init("example.", 28, 1);
        try fixture.edns(&.{});
        const edns = (try fixture.after(&test_fixture.zone, null)).?;
        try fixture.check(&edns, 0);
        try testing.expectEqual(@as(u16, 1), fixture.response.header.counts[3]);
    }

    // SPEC §3.2–3.5: RFC6761 wins over AAAA suppression; numeric NODATA is supported.
    test "pipeline exposes cache seam and RFC6761 outranks NODATA" {
        var fixture: test_fixture.Fixture = undefined;
        try fixture.init("localhost.", 28, 3);
        const local = (try fixture.local()).?;
        try fixture.check(&local, 1);
        try testing.expectEqual(.rfc6761, local.source);
        var zone = test_fixture.zone;
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
        var fixture: test_fixture.Fixture = undefined;
        try fixture.init("localhost.", 1, 1);
        try testing.expectError(
            error.NoSpace,
            resolver.beforeCache(&fixture.request, &fixture.encoder, fixture.output[0..20]),
        );
        try fixture.init("example.", 28, 1);
        try testing.expectError(error.NoSpace, resolver.afterCache(
            &fixture.request,
            &test_fixture.zone,
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
        var fixture: test_fixture.Fixture = undefined;
        try fixture.init("example.", 28, 1);
        const cookie = .{ 0, 10, 0, 40 } ++ .{0xaa} ** 40;
        try fixture.edns(&cookie);
        const answer = (try fixture.after(&test_fixture.zone, null)).?;
        try fixture.check(&answer, 0);
        const opt = fixture.response.records[fixture.response.opt.?];
        try testing.expectEqualSlices(u8, &cookie, answer.bytes[opt.data_start..opt.data_end]);
    }
};
