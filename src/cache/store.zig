//! Fixed stdlib columns retain stable slots and intrusive LRU links.
//! Packet ownership belongs to the cache's bounded size-class storage.
const builtin = @import("builtin");
const test_fixture = @import("../testing/cache.zig");
const std = @import("std");
const Wyhash = std.hash.Wyhash;
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const resolver = @import("../resolver.zig");
const wire = @import("../wire.zig");
const packets = @import("packets.zig");

pub const Key = struct {
    name: wire.Name,
    kind: wire.RecordType,
    class: u16,
    dnssec: enum { ordinary, requested },

    pub fn init(self: *Key, request: *const resolver.Request) void {
        self.name = request.name;
        self.kind = request.kind;
        self.class = request.class;
        self.dnssec = .ordinary;
        if (request.packet.opt) |index| {
            if (request.packet.records[index].ttl_s & wire.edns_dnssec_ok != 0)
                self.dnssec = .requested;
        }
    }

    pub fn fingerprint(self: *const Key) u64 {
        const metadata_bytes = 2 * @sizeOf(u16) + @sizeOf(u8);
        var canonical: [wire.names.name_bytes_max + metadata_bytes]u8 = undefined;
        // The metadata suffix extends a maximum-length name beyond u8.
        const length: usize = self.name.length;
        // Label lengths are below ASCII letters. Fold data only through the initialized name.
        for (self.name.wire(), canonical[0..length]) |byte, *target| {
            target.* = std.ascii.toLower(byte);
        }
        std.mem.writeInt(u16, canonical[length..][0..2], @intFromEnum(self.kind), .little);
        std.mem.writeInt(u16, canonical[length + 2 ..][0..2], self.class, .little);
        canonical[length + 4] = @intFromEnum(self.dnssec);
        // Zero marks a vacant slot, so a hashed zero becomes one. Key equality resolves collisions.
        const value = Wyhash.hash(0, canonical[0 .. length + metadata_bytes]);
        return if (value == 0) 1 else value;
    }

    fn eql(self: *const Key, other: *const Key) bool {
        if (self.kind != other.kind) return false;
        if (self.class != other.class) return false;
        if (self.dnssec != other.dnssec) return false;
        return self.name.eql(&other.name);
    }
};

pub const Entry = struct {
    key: Key = undefined,
    fingerprint: u64 = 0,
    bytes: ?[]u8 = null,
    packet_class: u8 = 0,
    inserted_s: u64 = 0,
    lifetime_s: u32 = 0,
    category: enum { answer, failure } = .answer,
    previous: ?u32 = null,
    next: ?u32 = null,

    pub fn age(self: *const Entry, now_s: u64) u64 {
        // The event thread supplies monotonic whole seconds, not wall-clock time.
        assert(now_s >= self.inserted_s);
        return now_s - self.inserted_s;
    }

    pub fn stale(self: *const Entry, now_s: u64, grace_s: u32) bool {
        if (grace_s == 0) return false;
        if (self.category == .failure) return false;
        const elapsed_s = self.age(now_s);
        if (elapsed_s < self.lifetime_s) return false;
        return elapsed_s - self.lifetime_s < grace_s;
    }
};

pub const IndexContext = struct {
    fingerprints: []const u64,

    pub fn hash(self: IndexContext, index: u32) u64 {
        return self.fingerprints[index];
    }

    pub fn eql(_: IndexContext, source: u32, target: u32) bool {
        return source == target;
    }
};

pub const LookupContext = struct {
    bank: *const Bank,

    pub fn hash(_: LookupContext, key: *const Key) u64 {
        return key.fingerprint();
    }

    pub fn eql(self: LookupContext, key: *const Key, index: u32) bool {
        return self.bank.entries.items(.key)[index].eql(key);
    }
};

pub const Bank = struct {
    pub const Context = IndexContext;

    entries: std.MultiArrayList(Entry) = .empty,
    index: std.HashMapUnmanaged(u32, void, IndexContext, 80) = .empty,
    index_removals: u32 = 0,
    first: ?u32 = null,
    last: ?u32 = null,

    pub fn init(self: *Bank, allocator: Allocator, capacity: u32) error{OutOfMemory}!void {
        self.* = .{};
        try self.entries.setCapacity(allocator, capacity);
        errdefer self.entries.deinit(allocator);
        self.entries.len = capacity;
        for (0..capacity) |index| self.entries.set(index, .{});
        try self.index.ensureTotalCapacityContext(allocator, capacity, self.indexContext());
    }

    pub fn deinit(self: *Bank, allocator: Allocator) void {
        self.index.deinit(allocator);
        self.entries.deinit(allocator);
        self.* = undefined;
    }

    pub fn find(self: *const Bank, key: *const Key) ?u32 {
        return self.index.getKeyAdapted(key, LookupContext{ .bank = self });
    }

    /// Publish into an empty stable slot.
    pub fn put(self: *Bank, index: u32, entry: *const Entry) void {
        assert(self.entries.items(.bytes)[index] == null);
        assert(entry.bytes != null);
        self.entries.set(index, entry.*);
        self.entries.items(.fingerprint)[index] = entry.key.fingerprint();
        // Each occupied slot owns one map key. Replacement removes its old key first.
        self.index.putAssumeCapacityNoClobberContext(index, {}, self.indexContext());
        self.prepend(index);
    }

    pub fn remove(self: *Bank, storage: *packets.Storage, index: u32) void {
        self.unlink(index);
        self.removeIndex(index);
        storage.destroy(
            self.entries.items(.bytes)[index].?,
            self.entries.items(.packet_class)[index],
        );
        self.entries.set(index, .{});
    }

    /// Transfer a block only after all fallible response work succeeds.
    pub fn take(self: *Bank, index: u32) []u8 {
        const bytes = self.entries.items(.bytes)[index].?;
        self.unlink(index);
        self.removeIndex(index);
        self.entries.set(index, .{});
        return bytes;
    }

    pub fn touch(self: *Bank, index: u32) void {
        self.unlink(index);
        self.prepend(index);
    }

    pub fn slot(self: *const Bank, key: *const Key) u32 {
        if (self.find(key)) |index| return index;
        if (self.index.count() == self.entries.len) return self.last.?;
        if (std.mem.findScalar(u64, self.entries.items(.fingerprint), 0)) |index| {
            return @intCast(index);
        }
        unreachable;
    }

    fn removeIndex(self: *Bank, index: u32) void {
        const removed = self.index.removeContext(index, self.indexContext());
        assert(removed);
        self.index_removals += 1;
        // A subsequent insertion can consume a free bucket instead of the new tombstone.
        // Rehash before half the reserved spare buckets become tombstones.
        const limit = (self.index.capacity() - self.entries.len) / 2;
        if (self.index_removals < limit) return;
        self.index.rehash(self.indexContext());
        self.index_removals = 0;
    }

    fn indexContext(self: *const Bank) IndexContext {
        return .{ .fingerprints = self.entries.items(.fingerprint) };
    }

    fn prepend(self: *Bank, index: u32) void {
        assert(index < self.entries.len);
        const columns = self.entries.slice();
        assert(columns.items(.bytes)[index] != null);
        columns.items(.previous)[index] = null;
        columns.items(.next)[index] = self.first;
        if (self.first) |first| columns.items(.previous)[first] = index else self.last = index;
        self.first = index;
    }

    fn unlink(self: *Bank, index: u32) void {
        assert(index < self.entries.len);
        assert(self.first != null);
        assert(self.last != null);
        const columns = self.entries.slice();
        assert(columns.items(.bytes)[index] != null);
        const previous = columns.items(.previous)[index];
        const next = columns.items(.next)[index];
        if (previous) |value| {
            columns.items(.next)[value] = next;
        } else self.first = next;
        if (next) |value| {
            columns.items(.previous)[value] = previous;
        } else self.last = previous;
    }
};

comptime {
    if (builtin.is_test) _ = ResolverTestsCacheIndex;
}

const ResolverTestsCacheIndex = struct {
    const testing = std.testing;

    fn keyInit(key: *Key, index: u16) !void {
        var text: [32]u8 = undefined;
        try key.name.fromText(try std.fmt.bufPrint(&text, "key{d}.example.", .{index}));
        key.kind = .a;
        key.class = 1;
        key.dnssec = .ordinary;
    }

    // SPEC §3.7; RFC 4343 §2: fingerprints cover initialized framed names and every
    // key dimension.
    test "cache fingerprint folds case excludes tails and preserves binary framing" {
        var first: Key = undefined;
        var other: Key = undefined;
        try keyInit(&first, 0);
        other = first;
        try other.name.fromText("KEY0.EXAMPLE.");
        @memset(first.name.bytes[first.name.length..], 0xaa);
        @memset(other.name.bytes[other.name.length..], 0x55);
        try testing.expectEqual(first.fingerprint(), other.fingerprint());
        try testing.expect(first.fingerprint() != 0);
        other.kind = .aaaa;
        try testing.expect(first.fingerprint() != other.fingerprint());
        other = first;
        other.class = 3;
        try testing.expect(first.fingerprint() != other.fingerprint());
        other = first;
        other.dnssec = .requested;
        try testing.expect(first.fingerprint() != other.fingerprint());
        other = first;
        first.name = .{};
        try first.name.append(&.{ 3, 'a', '.', 'b', 0 });
        try other.name.fromText("a.b.");
        try testing.expect(first.fingerprint() != other.fingerprint());
        first.name.bytes[2] = 0;
        try testing.expect(first.fingerprint() != other.fingerprint());
        first.name = .{ .length = 255 };
        var offset: usize = 0;
        for ([_]u8{ 63, 63, 63, 61 }) |length| {
            first.name.bytes[offset] = length;
            offset += 1;
            @memset(first.name.bytes[offset..][0..length], 'A');
            offset += length;
        }
        first.name.bytes[offset] = 0;
        other = first;
        for (other.name.bytes[0..254]) |*byte| byte.* = std.ascii.toLower(byte.*);
        try testing.expectEqual(first.fingerprint(), other.fingerprint());
    }

    // SPEC §§1.11, 3.7: stable slots, collisions, removal, reuse, and LRU.
    test "cache fixed hash index collisions stable slots and slot reuse" {
        for ([_]u32{ 1, 3, 17, 33 }) |capacity| {
            var packet_storage: test_fixture.cache.packets.Storage = undefined;
            try packet_storage.init(testing.allocator, 64 * 1024);
            defer packet_storage.deinit(testing.allocator);
            var bank: Bank = .{};
            try bank.init(testing.allocator, capacity);
            defer bank.deinit(testing.allocator);
            try testing.expectEqual(capacity, bank.entries.len);
            try testing.expectEqual(capacity, bank.entries.capacity);
            var key: Key = undefined;
            try keyInit(&key, 500);
            try testing.expectEqual(null, bank.find(&key));
            for (0..capacity) |index| {
                try keyInit(&key, @intCast(index));
                try testing.expectEqual(index, bank.slot(&key));
                bank.put(@intCast(index), &.{
                    .key = key,
                    .bytes = try packet_storage.copy(&.{42}),
                });
            }
            // Rebuild after each forced full-hash collision without changing keys or slot identity.
            @memset(bank.entries.items(.fingerprint), key.fingerprint());
            bank.index.rehash(Bank.Context{ .fingerprints = bank.entries.items(.fingerprint) });
            try testing.expectEqual(capacity - 1, bank.find(&key).?);
            var missing = key;
            missing.kind = .aaaa;
            @memset(bank.entries.items(.fingerprint), missing.fingerprint());
            bank.index.rehash(Bank.Context{ .fingerprints = bank.entries.items(.fingerprint) });
            try testing.expectEqual(null, bank.find(&missing));
            missing = key;
            missing.class = 3;
            @memset(bank.entries.items(.fingerprint), missing.fingerprint());
            bank.index.rehash(Bank.Context{ .fingerprints = bank.entries.items(.fingerprint) });
            try testing.expectEqual(null, bank.find(&missing));
            missing = key;
            missing.dnssec = .requested;
            @memset(bank.entries.items(.fingerprint), missing.fingerprint());
            bank.index.rehash(Bank.Context{ .fingerprints = bank.entries.items(.fingerprint) });
            try testing.expectEqual(null, bank.find(&missing));
            for (
                bank.entries.items(.key),
                bank.entries.items(.fingerprint),
            ) |*stored, *fingerprint| {
                fingerprint.* = stored.fingerprint();
            }
            bank.index.rehash(Bank.Context{ .fingerprints = bank.entries.items(.fingerprint) });
            for (0..capacity) |index| {
                try keyInit(&key, @intCast(index));
                try testing.expectEqual(index, bank.find(&key).?);
            }
            bank.touch(0);
            try testing.expectEqual(0, bank.first.?);
            try testing.expectEqual(if (capacity == 1) @as(u32, 0) else 1, bank.last.?);
            bank.remove(&packet_storage, capacity - 1);
            try testing.expectEqual(0, bank.entries.items(.fingerprint)[capacity - 1]);
            try testing.expectEqual(null, bank.find(&key));
            try testing.expectEqual(capacity - 1, bank.slot(&key));
            bank.put(capacity - 1, &.{
                .key = key,
                .bytes = try packet_storage.copy(&.{43}),
            });
            try testing.expectEqual(capacity - 1, bank.find(&key).?);
            try testing.expectEqual(capacity - 1, bank.first.?);
            const owned = bank.take(capacity - 1);
            try testing.expectEqual(capacity - 1, bank.index.count());
            try testing.expectEqual(null, bank.find(&key));
            bank.put(capacity - 1, &.{ .key = key, .bytes = owned });
            try testing.expectEqual(capacity - 1, bank.find(&key).?);
        }
    }

    // SPEC §1.3: the smallest bank includes the minimum hash allocation within its
    // per-slot budget.
    test "cache hash metadata stays bounded at small growth and maximum capacities" {
        for ([_]u32{ 1, 2, 3, 6, 7, 12, 13, 25, 26, 128, 1024, 10000, 100000 }) |capacity| {
            var allocator = testing.FailingAllocator.init(testing.allocator, .{});
            var bank: Bank = .{};
            try bank.init(allocator.allocator(), capacity);
            defer bank.deinit(allocator.allocator());
            try testing.expectEqual(2, allocator.allocations);
            try testing.expect(allocator.allocated_bytes <= 384 * @as(usize, capacity));
            try testing.expectEqual(0, bank.index.count());
        }
    }

    // SPEC §1.3: metadata includes the fixed stdlib index, not just columns or the
    // padded Entry size.
    test "cache metadata byte budget includes the preallocated hash index" {
        var index_allocator = testing.FailingAllocator.init(testing.allocator, .{});
        var index: std.AutoHashMapUnmanaged(u32, void) = .empty;
        try index.ensureTotalCapacity(
            index_allocator.allocator(),
            test_fixture.zone.cache.?.capacity,
        );
        defer index.deinit(index_allocator.allocator());
        var allocator = testing.FailingAllocator.init(testing.allocator, .{});
        var cache: test_fixture.cache.Cache = undefined;
        try cache.init(allocator.allocator(), &test_fixture.zone);
        defer cache.deinit();
        const bytes = std.MultiArrayList(test_fixture.cache.Entry).capacityInBytes(
            test_fixture.zone.cache.?.capacity,
        );
        const bank_bytes = bytes + index_allocator.allocated_bytes;
        const total_bytes = 2 * bank_bytes + test_fixture.zone.cache.?.packet_bytes_max;
        try testing.expectEqual(total_bytes, allocator.allocated_bytes);
        try testing.expect(bank_bytes <= 384 * test_fixture.zone.cache.?.capacity);
    }

    // SPEC §§1.10, 3.7: unique-name churn retains free buckets without allocations.
    test "cache hash churn retains a free bucket reserve without allocations" {
        for ([_]u32{ 1, 6, 13, 128 }) |capacity| {
            var allocator = testing.FailingAllocator.init(testing.allocator, .{});
            var packet_storage: test_fixture.cache.packets.Storage = undefined;
            try packet_storage.init(allocator.allocator(), 64 * 1024);
            defer packet_storage.deinit(allocator.allocator());
            var bank: Bank = .{};
            try bank.init(allocator.allocator(), capacity);
            defer bank.deinit(allocator.allocator());
            var key: Key = undefined;
            for (0..capacity) |index| {
                try keyInit(&key, @intCast(index));
                bank.put(
                    @intCast(index),
                    &.{ .key = key, .bytes = try packet_storage.copy(&.{42}) },
                );
            }
            const allocations = allocator.alloc_index;
            allocator.fail_index = allocations;
            const reserve = (bank.index.capacity() - capacity) / 2;
            for (0..4 * bank.index.capacity()) |index| {
                const slot = bank.last.?;
                const owned = bank.take(slot);
                try testing.expectEqual(capacity - 1, bank.index.count());
                try keyInit(&key, @intCast(capacity + index));
                try testing.expectEqual(null, bank.find(&key));
                bank.put(slot, &.{ .key = key, .bytes = owned });
                try testing.expectEqual(slot, bank.find(&key).?);
                var free: u32 = 0;
                for (bank.index.metadata.?[0..bank.index.capacity()]) |metadata| {
                    if (metadata.isFree()) free += 1;
                }
                if (free < reserve) {
                    std.debug.print("free buckets={d}, required={d}\n", .{ free, reserve });
                    return error.FreeBucketReserveLost;
                }
            }
            try testing.expectEqual(allocations, allocator.alloc_index);
            try testing.expect(!allocator.has_induced_failure);
        }
    }
};
