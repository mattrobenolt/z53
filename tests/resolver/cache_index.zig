const std = @import("std");
const f = @import("cache_fixture.zig");
const testing = std.testing;
const Bank = @TypeOf(@as(f.cache.Cache, undefined).positive);
const Key = @TypeOf(@as(f.cache.Entry, undefined).key);

fn keyInit(key: *Key, index: u16) !void {
    var text: [32]u8 = undefined;
    try key.name.fromText(try std.fmt.bufPrint(&text, "key{d}.example.", .{index}));
    key.kind = 1;
    key.class = 1;
    key.dnssec = .ordinary;
}

// SPEC §3.7; RFC 4343 §2: fingerprints cover initialized framed names and every key dimension.
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
    other.kind = 28;
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
        var packets: f.cache.packets.Storage = undefined;
        try packets.init(testing.allocator, 64 * 1024);
        defer packets.deinit(testing.allocator);
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
                .bytes = try packets.copy(&.{42}),
            });
        }
        // Rebuild after each forced full-hash collision without changing keys or slot identity.
        @memset(bank.entries.items(.fingerprint), key.fingerprint());
        bank.index.rehash(Bank.Context{ .fingerprints = bank.entries.items(.fingerprint) });
        try testing.expectEqual(capacity - 1, bank.find(&key).?);
        var missing = key;
        missing.kind = 28;
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
        for (bank.entries.items(.key), bank.entries.items(.fingerprint)) |*stored, *fingerprint| {
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
        bank.remove(&packets, capacity - 1);
        try testing.expectEqual(0, bank.entries.items(.fingerprint)[capacity - 1]);
        try testing.expectEqual(null, bank.find(&key));
        try testing.expectEqual(capacity - 1, bank.slot(&key));
        bank.put(capacity - 1, &.{
            .key = key,
            .bytes = try packets.copy(&.{43}),
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

// SPEC §1.3: the smallest bank includes the minimum hash allocation within its per-slot budget.
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

// SPEC §1.3: metadata includes the fixed stdlib index, not just columns or the padded Entry size.
test "cache metadata byte budget includes the preallocated hash index" {
    var index_allocator = testing.FailingAllocator.init(testing.allocator, .{});
    var index: std.AutoHashMapUnmanaged(u32, void) = .empty;
    try index.ensureTotalCapacity(index_allocator.allocator(), f.zone.cache.?.capacity);
    defer index.deinit(index_allocator.allocator());
    var allocator = testing.FailingAllocator.init(testing.allocator, .{});
    var cache: f.cache.Cache = undefined;
    try cache.init(allocator.allocator(), &f.zone);
    defer cache.deinit();
    const bytes = std.MultiArrayList(f.cache.Entry).capacityInBytes(f.zone.cache.?.capacity);
    const bank_bytes = bytes + index_allocator.allocated_bytes;
    const total_bytes = 2 * bank_bytes + f.zone.cache.?.packet_bytes_max;
    try testing.expectEqual(total_bytes, allocator.allocated_bytes);
    try testing.expect(bank_bytes <= 384 * f.zone.cache.?.capacity);
}

// SPEC §§1.10, 3.7: unique-name churn retains free buckets without allocations.
test "cache hash churn retains a free bucket reserve without allocations" {
    for ([_]u32{ 1, 6, 13, 128 }) |capacity| {
        var allocator = testing.FailingAllocator.init(testing.allocator, .{});
        var packets: f.cache.packets.Storage = undefined;
        try packets.init(allocator.allocator(), 64 * 1024);
        defer packets.deinit(allocator.allocator());
        var bank: Bank = .{};
        try bank.init(allocator.allocator(), capacity);
        defer bank.deinit(allocator.allocator());
        var key: Key = undefined;
        for (0..capacity) |index| {
            try keyInit(&key, @intCast(index));
            bank.put(@intCast(index), &.{ .key = key, .bytes = try packets.copy(&.{42}) });
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
