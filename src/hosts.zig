//! Bounded, caller-owned hosts snapshots. Only replacement writes the inactive table.
const builtin = @import("builtin");
const test_fixture = @import("testing/resolver.zig");
const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;

const wire = @import("wire.zig");

pub const source_bytes_max = 1024 * 1024;
pub const entries_max = 16384;

pub const Error = error{ SourceTooLarge, TableFull };
pub const Reload = enum { unchanged, replaced };

const Address = union(enum) {
    ipv4: [4]u8,
    ipv6: [16]u8,
};

pub const Entry = struct {
    name: wire.Name,
    reverse: wire.Name,
    address: Address,

    pub fn matches(self: *const Entry, name: *const wire.Name, kind: wire.RecordType) bool {
        return switch (kind) {
            .a => switch (self.address) {
                .ipv4 => self.name.eql(name),
                .ipv6 => false,
            },
            .aaaa => switch (self.address) {
                .ipv4 => false,
                .ipv6 => self.name.eql(name),
            },
            .ptr => self.reverse.eql(name),
            else => false,
        };
    }

    pub fn write(
        self: *const Entry,
        encoder: *wire.Encoder,
        kind: wire.RecordType,
    ) wire.Error!void {
        switch (kind) {
            .a => try encoder.bytes(&self.address.ipv4),
            .aaaa => try encoder.bytes(&self.address.ipv6),
            .ptr => try encoder.name(&self.name, .allowed),
            else => unreachable,
        }
    }
};

pub const Table = struct {
    list: std.ArrayList(Entry) = .empty,

    pub fn entries(self: *const Table) []const Entry {
        return self.list.items;
    }

    /// A failed parse invalidates this table only; the Store's active snapshot stays valid.
    fn parse(self: *Table, source: []const u8) Error!void {
        assert(self.list.capacity <= entries_max);
        // Retain entry storage instead of poisoning it before the next parse.
        self.list.items.len = 0;
        if (source.len > source_bytes_max) return error.SourceTooLarge;
        var lines = std.mem.splitScalar(u8, source, '\n');
        while (lines.next()) |text| try self.line(text);
    }

    fn line(self: *Table, text: []const u8) Error!void {
        const end = std.mem.indexOfScalar(u8, text, '#') orelse text.len;
        var tokens = std.mem.tokenizeAny(u8, text[0..end], " \t\r");
        const literal = tokens.next() orelse return;
        var address: Address = undefined;
        if (Io.net.Ip4Address.parse(literal, 0)) |value| {
            address = .{ .ipv4 = value.bytes };
        } else |_| {
            const value = Io.net.Ip6Address.parse(literal, 0) catch return;
            // A scoped address cannot be represented in DNS AAAA RDATA.
            if (std.mem.indexOfScalar(u8, literal, '%') != null) return;
            address = .{ .ipv6 = value.bytes };
        }
        const aliases = tokens;
        var name: wire.Name = undefined;
        while (tokens.next()) |text_name| {
            parseName(&name, text_name) catch return;
        }
        var reverse: wire.Name = undefined;
        reverseName(&reverse, &address);
        tokens = aliases;
        while (tokens.next()) |text_name| {
            parseName(&name, text_name) catch unreachable;
            if (self.contains(&name, &reverse)) continue;
            self.list.appendBounded(.{
                .name = name,
                .reverse = reverse,
                .address = address,
            }) catch return error.TableFull;
        }
    }

    fn contains(self: *const Table, name: *const wire.Name, reverse: *const wire.Name) bool {
        for (self.entries()) |*entry| {
            if (!entry.name.eql(name)) continue;
            if (entry.reverse.eql(reverse)) return true;
        }
        return false;
    }
};

/// The event thread must complete readers before replacement or reuse of snapshots.
/// The runtime schedules load calls; no timer or asynchronous snapshot is owned here.
pub const Store = struct {
    tables: [2]Table,
    active: u1 = 0,
    mtime: ?i128 = null,

    pub fn init(self: *Store, first: []Entry, second: []Entry) void {
        assert(first.len > 0);
        assert(first.len == second.len);
        assert(first.len <= entries_max);
        const first_end = @intFromPtr(first.ptr) + first.len * @sizeOf(Entry);
        const second_end = @intFromPtr(second.ptr) + second.len * @sizeOf(Entry);
        if (@intFromPtr(first.ptr) < @intFromPtr(second.ptr)) {
            assert(first_end <= @intFromPtr(second.ptr));
        } else assert(second_end <= @intFromPtr(first.ptr));
        self.* = .{ .tables = .{
            .{ .list = .initBuffer(first) },
            .{ .list = .initBuffer(second) },
        } };
    }

    /// Allocate both snapshots once. Parse and reload never grow these lists.
    pub fn initCapacity(self: *Store, allocator: std.mem.Allocator) error{OutOfMemory}!void {
        self.* = .{ .tables = .{ .{}, .{} } };
        errdefer self.deinit(allocator);
        for (&self.tables) |*snapshot| {
            snapshot.list = try .initCapacity(allocator, entries_max);
        }
    }

    /// Release only storage from initCapacity. The init method borrows its buffers.
    pub fn deinit(self: *Store, allocator: std.mem.Allocator) void {
        for (&self.tables) |*snapshot| snapshot.list.deinit(allocator);
        self.* = undefined;
    }

    pub fn table(self: *const Store) *const Table {
        return &self.tables[self.active];
    }

    pub fn changed(self: *const Store, mtime: i128) bool {
        return self.mtime != mtime;
    }

    /// Caller supplies source_bytes_max + 1 bytes to detect growth beyond the bound.
    /// Read one opened regular file; a changed file is retried on the next check.
    pub fn load(
        self: *Store,
        io: Io,
        directory: Io.Dir,
        path: []const u8,
        buffer: []u8,
    ) (Error || Io.File.OpenError || Io.File.StatError ||
        Io.Dir.StatFileError || Io.File.ReadPositionalError ||
        error{ NotRegularFile, FileChanged })!Reload {
        assert(buffer.len > source_bytes_max);
        // Reject configured devices/FIFOs before open, which can otherwise block.
        const path_stat = try directory.statFile(io, path, .{});
        if (path_stat.kind != .file) return error.NotRegularFile;
        if (!self.changed(path_stat.mtime.nanoseconds)) return .unchanged;
        const file = try directory.openFile(io, path, .{});
        defer file.close(io);
        const before = try file.stat(io);
        if (before.kind != .file) return error.NotRegularFile;
        if (!self.changed(before.mtime.nanoseconds)) return .unchanged;
        if (before.size > source_bytes_max) return error.SourceTooLarge;
        const length = try file.readPositionalAll(io, buffer[0 .. source_bytes_max + 1], 0);
        if (length > source_bytes_max) return error.SourceTooLarge;
        const after = try file.stat(io);
        if (before.mtime.nanoseconds != after.mtime.nanoseconds) return error.FileChanged;
        if (before.ctime.nanoseconds != after.ctime.nanoseconds) return error.FileChanged;
        if (before.size != after.size) return error.FileChanged;
        if (length != after.size) return error.FileChanged;
        try self.replace(buffer[0..length], before.mtime.nanoseconds);
        return .replaced;
    }

    /// Publish only a complete parse. Failure preserves the old mtime for retries.
    pub fn replace(self: *Store, source: []const u8, mtime: i128) Error!void {
        const candidate = self.active ^ 1;
        try self.tables[candidate].parse(source);
        self.active = candidate;
        self.mtime = mtime;
    }
};

fn parseName(target: *wire.Name, text: []const u8) wire.Error!void {
    for (text) |byte| {
        if (std.ascii.isAlphanumeric(byte)) continue;
        switch (byte) {
            '-', '_', '.' => {},
            else => return error.InvalidName,
        }
    }
    try target.fromText(text);
    if (target.length == 1) return error.InvalidName;
    for (target.bytes[0..target.length]) |*byte| byte.* = std.ascii.toLower(byte.*);
}

fn reverseName(target: *wire.Name, address: *const Address) void {
    var text: [80]u8 = undefined;
    switch (address.*) {
        .ipv4 => |bytes| {
            const value = std.fmt.bufPrint(&text, "{d}.{d}.{d}.{d}.in-addr.arpa.", .{
                bytes[3], bytes[2], bytes[1], bytes[0],
            }) catch unreachable;
            target.fromText(value) catch unreachable;
        },
        .ipv6 => |bytes| {
            const digits = "0123456789abcdef";
            for (0..16) |index| {
                const byte = bytes[15 - index];
                text[index * 4 ..][0..4].* = .{ digits[byte & 15], '.', digits[byte >> 4], '.' };
            }
            @memcpy(text[64..73], "ip6.arpa.");
            target.fromText(text[0..73]) catch unreachable;
        },
    }
}

comptime {
    if (builtin.is_test) _ = ResolverTestsHosts;
}

const ResolverTestsHosts = struct {
    const testing = test_fixture.testing;
    const resolver = test_fixture.resolver;
    const hosts = resolver.hosts;

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
        try testing.expectEqual(@as(usize, 4), snapshot.store.table().entries().len);
        var name: wire.Name = undefined;
        try name.fromText("MAIN.");
        try testing.expect(snapshot.store.table().entries()[0].name.eql(&name));
        var long: [64]u8 = @splat('a');
        var source: [128]u8 = undefined;
        const invalid = try std.fmt.bufPrint(&source, "127.0.0.1 valid {s}\n", .{&long});
        try snapshot.store.replace(invalid, 2);
        try testing.expectEqual(@as(usize, 0), snapshot.store.table().entries().len);
    }

    // SPEC §3.5; RFC 1035 §3.4.1 and RFC 3596 §2.2: all matching address records and TTL.
    test "hosts A AAAA records TTL flags and type fallthrough" {
        var snapshot: Snapshot = undefined;
        try snapshot.init("192.0.2.1 Main alias\n192.0.2.2 main\n2001:db8::1 main\n");
        var fixture: test_fixture.Fixture = undefined;
        var zone = test_fixture.zone;
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
        var fixture: test_fixture.Fixture = undefined;
        const names = [_][]const u8{
            "1.2.0.192.in-addr.arpa.",
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
        };
        for (names) |name| {
            try fixture.init(name, 12, 1);
            const answer = (try fixture.after(&test_fixture.zone, snapshot.store.table())).?;
            try fixture.check(&answer, 2);
            for ([_][]const u8{ "main.", "alias." }, 0..) |alias, index| {
                var target: wire.Name = undefined;
                var expected: wire.Name = undefined;
                try expected.fromText(alias);
                try fixture.response.name(&target, fixture.response.records[index].data_start);
                try testing.expect(target.eql(&expected));
            }
        }
    }

    // SPEC §3.2–3.5: NODATA precedes hosts, non-IN falls through, disabled hosts never answer.
    test "hosts pipeline precedence and class policy" {
        var snapshot: Snapshot = undefined;
        try snapshot.init("2001:db8::1 example\n192.0.2.1 example\n");
        var fixture: test_fixture.Fixture = undefined;
        for ([_]u16{ 1, 3, 65280 }) |class| {
            try fixture.init("example.", 28, class);
            const answer = (try fixture.after(&test_fixture.zone, snapshot.store.table())).?;
            try fixture.check(&answer, 0);
            try testing.expectEqual(.nodata, answer.source);
        }
        for ([_]u16{ 3, 65280 }) |class| {
            try fixture.init("example.", 1, class);
            try testing.expectEqual(
                @as(?resolver.Answer, null),
                try fixture.after(&test_fixture.zone, snapshot.store.table()),
            );
        }
        var zone = test_fixture.zone;
        zone.hosts = null;
        try fixture.init("example.", 1, 1);
        try testing.expectEqual(
            @as(?resolver.Answer, null),
            try fixture.after(&zone, snapshot.store.table()),
        );
        try testing.expectEqual(
            @as(?resolver.Answer, null),
            try fixture.after(&test_fixture.zone, null),
        );
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
        try testing.expect(store.table().entries()[0].name.eql(&name));
        const oversized = try testing.allocator.alloc(u8, hosts.source_bytes_max + 1);
        defer testing.allocator.free(oversized);
        @memset(oversized, '\n');
        try testing.expectError(error.SourceTooLarge, store.replace(oversized, 2));
        try testing.expect(active == store.table());
        try testing.expectEqual(@as(?i128, 1), store.mtime);
        try store.replace("192.0.2.2 new\n", 2);
        try testing.expect(active != store.table());
        try testing.expect(!store.table().entries()[0].name.eql(&name));
        try testing.expect(!store.changed(2));
        try store.replace("# empty\ninvalid\n", 3);
        try testing.expectEqual(@as(usize, 0), store.table().entries().len);
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
        try testing.expectEqual(@as(usize, hosts.entries_max), store.table().entries().len);
        var fixture: test_fixture.Fixture = undefined;
        var zone = test_fixture.zone;
        zone.nodata = &.{};
        try fixture.init("same.", 28, 1);
        try testing.expectError(error.RewriteTooLarge, fixture.after(&zone, store.table()));
    }

    // SPEC §3.5: deployment-sized files retain every alias up to entries_max.
    test "hosts large deployment file retains fourteen thousand names and aliases" {
        const first = try testing.allocator.alloc(hosts.Entry, hosts.entries_max);
        defer testing.allocator.free(first);
        const second = try testing.allocator.alloc(hosts.Entry, hosts.entries_max);
        defer testing.allocator.free(second);
        const source = try testing.allocator.alloc(u8, hosts.source_bytes_max);
        defer testing.allocator.free(source);
        @memset(source, '\n');
        var writer: std.Io.Writer = .fixed(source);
        for (0..7000) |index|
            try writer.print("192.0.2.1 host{d}.example host{d}\n", .{ index, index });
        try writer.writeAll("192.0.2.1 host6999.example host6999\n");
        var store: hosts.Store = undefined;
        store.init(first, second);
        try store.replace(source, 1);
        try testing.expectEqual(14000, store.table().entries().len);
        var fixture: test_fixture.Fixture = undefined;
        for ([_][]const u8{ "host0.example.", "host6999.example.", "host6999." }) |name| {
            try fixture.init(name, 1, 1);
            const answer = (try fixture.after(&test_fixture.zone, store.table())).?;
            try fixture.check(&answer, 1);
            const record = fixture.response.records[0];
            try testing.expectEqualSlices(
                u8,
                &.{ 192, 0, 2, 1 },
                answer.bytes[record.data_start..record.data_end],
            );
        }
    }

    // SPEC §3.5, §3.9; RFC 7873 §4: hosts responses echo COOKIE, not just NODATA.
    test "hosts and RFC6761 echo EDNS COOKIE" {
        var snapshot: Snapshot = undefined;
        try snapshot.init("192.0.2.1 example\n");
        var fixture: test_fixture.Fixture = undefined;
        const cookie = [_]u8{ 0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8 };
        for ([_][]const u8{ "example.", "localhost." }) |name| {
            try fixture.init(name, 1, 1);
            try fixture.edns(&cookie);
            const answer = (try fixture.local()) orelse
                (try fixture.after(&test_fixture.zone, snapshot.store.table())).?;
            try fixture.check(&answer, 1);
            const opt = fixture.response.records[fixture.response.opt.?];
            try testing.expectEqual(@as(u16, 1400), opt.class);
            try testing.expectEqualSlices(u8, &cookie, answer.bytes[opt.data_start..opt.data_end]);
        }
    }
};

comptime {
    if (builtin.is_test) _ = ResolverTestsReload;
}

const ResolverTestsReload = struct {
    const hosts = test_fixture.resolver.hosts;
    const testing = std.testing;

    fn write(directory: std.Io.Dir, source: []const u8, seconds: i64) !void {
        try directory.writeFile(testing.io, .{ .sub_path = "hosts", .data = source });
        const file = try directory.openFile(testing.io, "hosts", .{});
        defer file.close(testing.io);
        try file.setTimestamps(testing.io, .{
            .modify_timestamp = .{ .new = .fromNanoseconds(@as(i96, seconds) * std.time.ns_per_s) },
        });
    }

    // SPEC §3.5: real file reads replace only changed snapshots and preserve deleted-file data.
    test "hosts file reload observes mtime and retains old table on I/O and capacity failure" {
        var temporary = testing.tmpDir(.{});
        defer temporary.cleanup();
        var first: [1]hosts.Entry = undefined;
        var second: [1]hosts.Entry = undefined;
        var store: hosts.Store = undefined;
        store.init(&first, &second);
        const source = try testing.allocator.alloc(u8, hosts.source_bytes_max + 1);
        defer testing.allocator.free(source);
        try write(temporary.dir, "192.0.2.1 old\n", 100);
        try testing.expectEqual(
            .replaced,
            try store.load(testing.io, temporary.dir, "hosts", source),
        );
        const active = store.table();
        try testing.expectEqual(
            .unchanged,
            try store.load(testing.io, temporary.dir, "hosts", source),
        );
        try testing.expect(active == store.table());
        try write(temporary.dir, "192.0.2.2 new\n", 100);
        try testing.expectEqual(
            .unchanged,
            try store.load(testing.io, temporary.dir, "hosts", source),
        );
        try write(temporary.dir, "192.0.2.2 new alias\n", 101);
        try testing.expectError(
            error.TableFull,
            store.load(testing.io, temporary.dir, "hosts", source),
        );
        try testing.expect(active == store.table());
        try testing.expectEqual(@as(?i128, 100 * std.time.ns_per_s), store.mtime);
        try write(temporary.dir, "192.0.2.2 new\n", 101);
        try testing.expectEqual(
            .replaced,
            try store.load(testing.io, temporary.dir, "hosts", source),
        );
        try testing.expect(active != store.table());
        const replaced = store.table();
        try temporary.dir.deleteFile(testing.io, "hosts");
        try testing.expectError(
            error.FileNotFound,
            store.load(testing.io, temporary.dir, "hosts", source),
        );
        try testing.expect(replaced == store.table());
        try testing.expectEqual(@as(?i128, 101 * std.time.ns_per_s), store.mtime);
        try write(temporary.dir, "# empty\n", 102);
        try testing.expectEqual(
            .replaced,
            try store.load(testing.io, temporary.dir, "hosts", source),
        );
        try testing.expectEqual(@as(usize, 0), store.table().entries().len);
    }

    // SPEC §1.11, §3.5: bound file size and reject nonregular sources without publication.
    test "hosts file size and regular file restrictions" {
        var temporary = testing.tmpDir(.{});
        defer temporary.cleanup();
        var first: [1]hosts.Entry = undefined;
        var second: [1]hosts.Entry = undefined;
        var store: hosts.Store = undefined;
        store.init(&first, &second);
        const source = try testing.allocator.alloc(u8, hosts.source_bytes_max + 1);
        defer testing.allocator.free(source);
        @memset(source, '\n');
        try write(temporary.dir, source, 100);
        try testing.expectError(
            error.SourceTooLarge,
            store.load(testing.io, temporary.dir, "hosts", source),
        );
        try testing.expectEqual(@as(?i128, null), store.mtime);
        try testing.expectError(
            error.NotRegularFile,
            store.load(testing.io, temporary.dir, ".", source),
        );
        try testing.expectEqual(@as(?i128, null), store.mtime);
        try write(temporary.dir, source[0..hosts.source_bytes_max], 101);
        try testing.expectEqual(
            .replaced,
            try store.load(testing.io, temporary.dir, "hosts", source),
        );
    }

    const Fault = struct {
        var calls: u8 = 0;

        fn changed(
            userdata: ?*anyopaque,
            file: std.Io.File,
        ) std.Io.File.StatError!std.Io.File.Stat {
            var result = try testing.io.vtable.fileStat(userdata, file);
            calls += 1;
            if (calls == 2) result.mtime.nanoseconds += std.time.ns_per_s;
            return result;
        }

        fn unreadable(
            _: ?*anyopaque,
            _: std.Io.File,
            _: []const []u8,
            _: u64,
        ) std.Io.File.ReadPositionalError!usize {
            return error.InputOutput;
        }
    };

    // SPEC §3.5: deterministic Io faults reject a torn read and never publish an I/O failure.
    test "hosts detects mid-read changes and read failure before snapshot publication" {
        var temporary = testing.tmpDir(.{});
        defer temporary.cleanup();
        var first: [1]hosts.Entry = undefined;
        var second: [1]hosts.Entry = undefined;
        var store: hosts.Store = undefined;
        store.init(&first, &second);
        try store.replace("192.0.2.1 old\n", 1);
        const active = store.table();
        const source = try testing.allocator.alloc(u8, hosts.source_bytes_max + 1);
        defer testing.allocator.free(source);
        try write(temporary.dir, "192.0.2.2 new\n", 100);
        var vtable = testing.io.vtable.*;
        vtable.fileStat = Fault.changed;
        const io: std.Io = .{ .userdata = testing.io.userdata, .vtable = &vtable };
        Fault.calls = 0;
        try testing.expectError(error.FileChanged, store.load(io, temporary.dir, "hosts", source));
        try testing.expect(active == store.table());
        try testing.expectEqual(@as(?i128, 1), store.mtime);
        vtable.fileStat = testing.io.vtable.fileStat;
        vtable.fileReadPositional = Fault.unreadable;
        try testing.expectError(error.InputOutput, store.load(io, temporary.dir, "hosts", source));
        try testing.expect(active == store.table());
        try testing.expectEqual(@as(?i128, 1), store.mtime);
    }
};

comptime {
    if (builtin.is_test) _ = ResolverTestsOwnership;
}

const ResolverTestsOwnership = struct {
    const testing = std.testing;

    // SPEC §§1, 3.5: partial startup failures release both bounded snapshots.
    test "hosts owned snapshot allocation failures release partial storage" {
        try testing.checkAllAllocationFailures(testing.allocator, allocate, .{});
    }

    fn allocate(allocator: std.mem.Allocator) !void {
        var store: Store = undefined;
        try store.initCapacity(allocator);
        defer store.deinit(allocator);
        for (&store.tables) |*snapshot| {
            try testing.expectEqual(@as(usize, entries_max), snapshot.list.capacity);
            try testing.expectEqual(@as(usize, 0), snapshot.entries().len);
        }
    }

    // SPEC §§1, 3.5: owned snapshots never allocate during replacement or lookup.
    test "hosts owned snapshots retain their allocations across replacement" {
        var allocator = testing.FailingAllocator.init(testing.allocator, .{});
        var store: Store = undefined;
        try store.initCapacity(allocator.allocator());
        defer store.deinit(allocator.allocator());
        const allocations = allocator.alloc_index;
        allocator.fail_index = allocations;
        try store.replace("192.0.2.1 first alias\n", 1);
        try testing.expectEqual(@as(usize, 2), store.table().entries().len);
        try store.replace("192.0.2.2 second\n", 2);
        try testing.expectEqual(@as(usize, 1), store.table().entries().len);
        try testing.expectEqual(allocations, allocator.alloc_index);
        try testing.expect(!allocator.has_induced_failure);
    }
};
