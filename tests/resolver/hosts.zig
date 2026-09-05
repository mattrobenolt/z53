const std = @import("std");
const f = @import("fixture.zig");
const testing = f.testing;
const resolver = f.resolver;
const hosts = resolver.hosts;
const wire = f.wire;

const Snapshot = struct {
    first: [16]hosts.Entry,
    second: [16]hosts.Entry,
    store: hosts.Store,

    fn init(self: *Snapshot, source: []const u8) !void {
        self.store.init(&self.first, &self.second);
        try self.store.replace(source, 1);
    }
};

// SPEC §3.5: parse aliases, comments, IPv4/IPv6, deduplicate, and skip entire bad lines.
test "hosts parser skips invalid lines and folds aliases" {
    var snapshot: Snapshot = undefined;
    try snapshot.init(
        "# comment\n127.0.0.2 Main alias # comment\r\n" ++
            "127.0.0.2 MAIN.\n2001:db8::1 main v6\n" ++
            "bad invalid\n999.1.2.3 invalid\n::g invalid\n" ++
            "127.0.0.3 valid bad..name\n127.0.0.3 valid bad\x00name\n" ++
            "fe80::1%3 scoped\n127.0.0.4\n127.0.0.5 .\n",
    );
    try testing.expectEqual(@as(u16, 4), snapshot.store.table().count);
    var name: wire.Name = undefined;
    try name.fromText("MAIN.");
    try testing.expect(snapshot.store.table().entries()[0].name.equal(&name));
    var long: [64]u8 = @splat('a');
    var source: [128]u8 = undefined;
    const invalid = try std.fmt.bufPrint(&source, "127.0.0.1 valid {s}\n", .{&long});
    try snapshot.store.replace(invalid, 2);
    try testing.expectEqual(@as(u16, 0), snapshot.store.table().count);
}

// SPEC §3.5; RFC 1035 §3.4.1 and RFC 3596 §2.2: all matching address records and TTL.
test "hosts A AAAA records TTL flags and type fallthrough" {
    var snapshot: Snapshot = undefined;
    try snapshot.init("192.0.2.1 Main alias\n192.0.2.2 main\n2001:db8::1 main\n");
    var fixture: f.Fixture = undefined;
    var zone = f.zone;
    zone.nodata = &.{};
    for ([_]u16{ 1, 28 }) |kind| {
        try fixture.init("MaIn.", kind, 1);
        const answer = (try fixture.after(&zone, snapshot.store.table())).?;
        try fixture.check(&answer, if (kind == 1) 2 else 1);
        try testing.expectEqual(.hosts, answer.source);
        try testing.expect(answer.source.rotatable());
        const record = fixture.response.records[0];
        try testing.expectEqual(@as(u32, 30), record.ttl_s);
        const expected: []const u8 = if (kind == 1)
            &.{ 192, 0, 2, 1 }
        else
            &.{ 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
        try testing.expectEqualSlices(
            u8,
            expected,
            answer.bytes[record.data_start..record.data_end],
        );
    }
    zone.hosts.?.ttl = 77;
    try fixture.init("alias.", 1, 1);
    const changed = (try fixture.after(&zone, snapshot.store.table())).?;
    try fixture.check(&changed, 1);
    try testing.expectEqual(@as(u32, 77), fixture.response.records[0].ttl_s);
    for ([_]u16{ 28, 16, 255 }) |kind| {
        try fixture.init("alias.", kind, 1);
        try testing.expectEqual(
            @as(?resolver.Answer, null),
            try fixture.after(&zone, snapshot.store.table()),
        );
    }
    try fixture.init("absent.", 1, 1);
    try testing.expectEqual(
        @as(?resolver.Answer, null),
        try fixture.after(&zone, snapshot.store.table()),
    );
}

// SPEC §3.5; RFC 1035 §3.5 and RFC 3596 §2.5: reverse IPv4 octets and IPv6 nibbles.
test "hosts PTR synthesizes all aliases for IPv4 and IPv6" {
    var snapshot: Snapshot = undefined;
    try snapshot.init("192.0.2.1 Main alias\n2001:db8::1 main alias\n");
    var fixture: f.Fixture = undefined;
    const names = [_][]const u8{
        "1.2.0.192.in-addr.arpa.",
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
    };
    for (names) |name| {
        try fixture.init(name, 12, 1);
        const answer = (try fixture.after(&f.zone, snapshot.store.table())).?;
        try fixture.check(&answer, 2);
        for ([_][]const u8{ "main.", "alias." }, 0..) |alias, index| {
            var target: wire.Name = undefined;
            var expected: wire.Name = undefined;
            try expected.fromText(alias);
            try fixture.response.name(&target, fixture.response.records[index].data_start);
            try testing.expect(target.equal(&expected));
        }
    }
}

// SPEC §3.2–3.5: NODATA precedes hosts, non-IN falls through, disabled hosts never answer.
test "hosts pipeline precedence and class policy" {
    var snapshot: Snapshot = undefined;
    try snapshot.init("2001:db8::1 example\n192.0.2.1 example\n");
    var fixture: f.Fixture = undefined;
    for ([_]u16{ 1, 3, 65280 }) |class| {
        try fixture.init("example.", 28, class);
        const answer = (try fixture.after(&f.zone, snapshot.store.table())).?;
        try fixture.check(&answer, 0);
        try testing.expectEqual(.nodata, answer.source);
    }
    for ([_]u16{ 3, 65280 }) |class| {
        try fixture.init("example.", 1, class);
        try testing.expectEqual(
            @as(?resolver.Answer, null),
            try fixture.after(&f.zone, snapshot.store.table()),
        );
    }
    var zone = f.zone;
    zone.hosts = null;
    try fixture.init("example.", 1, 1);
    try testing.expectEqual(
        @as(?resolver.Answer, null),
        try fixture.after(&zone, snapshot.store.table()),
    );
    try testing.expectEqual(@as(?resolver.Answer, null), try fixture.after(&f.zone, null));
}

// SPEC §3.5: successful swaps remove deleted names; failed loads preserve data and mtime.
test "bounded replacement is atomic and failed mtime remains retryable" {
    var first: [1]hosts.Entry = undefined;
    var second: [1]hosts.Entry = undefined;
    var store: hosts.Store = undefined;
    store.init(&first, &second);
    try testing.expect(store.changed(1));
    try store.replace("192.0.2.1 old\n", 1);
    try testing.expect(!store.changed(1));
    const active = store.table();
    try testing.expectError(error.TableFull, store.replace("192.0.2.2 new alias\n", 2));
    try testing.expect(active == store.table());
    try testing.expect(store.changed(2));
    var name: wire.Name = undefined;
    try name.fromText("old.");
    try testing.expect(store.table().entries()[0].name.equal(&name));
    const oversized = try testing.allocator.alloc(u8, hosts.source_bytes_max + 1);
    defer testing.allocator.free(oversized);
    @memset(oversized, '\n');
    try testing.expectError(error.SourceTooLarge, store.replace(oversized, 2));
    try testing.expect(active == store.table());
    try testing.expectEqual(@as(?i128, 1), store.mtime);
    try store.replace("192.0.2.2 new\n", 2);
    try testing.expect(active != store.table());
    try testing.expect(!store.table().entries()[0].name.equal(&name));
    try testing.expect(!store.changed(2));
    try store.replace("# empty\ninvalid\n", 3);
    try testing.expectEqual(@as(u16, 0), store.table().count);
}

// SPEC §1.10, §3.5, §3.9: maximum source/entry bounds and unservable answer rejection.
test "hosts maximum bounds and oversized synthetic answer" {
    const first = try testing.allocator.alloc(hosts.Entry, hosts.entries_max);
    defer testing.allocator.free(first);
    const second = try testing.allocator.alloc(hosts.Entry, hosts.entries_max);
    defer testing.allocator.free(second);
    const source = try testing.allocator.alloc(u8, hosts.source_bytes_max);
    defer testing.allocator.free(source);
    @memset(source, '\n');
    var writer: std.Io.Writer = .fixed(source);
    for (0..hosts.entries_max) |index| try writer.print("2001:db8::{x} same\n", .{index});
    var store: hosts.Store = undefined;
    store.init(first, second);
    try store.replace(source, 1);
    try testing.expectEqual(@as(u16, hosts.entries_max), store.table().count);
    var fixture: f.Fixture = undefined;
    var zone = f.zone;
    zone.nodata = &.{};
    try fixture.init("same.", 28, 1);
    try testing.expectError(error.RewriteTooLarge, fixture.after(&zone, store.table()));
}

// SPEC §3.5, §3.9; RFC 7873 §4: hosts responses echo COOKIE, not just NODATA.
test "hosts and RFC6761 echo EDNS COOKIE" {
    var snapshot: Snapshot = undefined;
    try snapshot.init("192.0.2.1 example\n");
    var fixture: f.Fixture = undefined;
    const cookie = [_]u8{ 0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8 };
    for ([_][]const u8{ "example.", "localhost." }) |name| {
        try fixture.init(name, 1, 1);
        try fixture.edns(&cookie);
        const answer = (try fixture.local()) orelse
            (try fixture.after(&f.zone, snapshot.store.table())).?;
        try fixture.check(&answer, 1);
        const opt = fixture.response.records[fixture.response.opt.?];
        try testing.expectEqual(@as(u16, 1400), opt.class);
        try testing.expectEqualSlices(u8, &cookie, answer.bytes[opt.data_start..opt.data_end]);
    }
}
