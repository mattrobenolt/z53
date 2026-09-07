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
test "cache dense index first last tails collisions and slot reuse" {
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
        // Every candidate collides with the final key, including vector and scalar tails.
        @memset(bank.entries.items(.fingerprint), key.fingerprint());
        try testing.expectEqual(capacity - 1, bank.find(&key).?);
        var missing = key;
        missing.kind = 28;
        @memset(bank.entries.items(.fingerprint), missing.fingerprint());
        try testing.expectEqual(null, bank.find(&missing));
        missing = key;
        missing.class = 3;
        @memset(bank.entries.items(.fingerprint), missing.fingerprint());
        try testing.expectEqual(null, bank.find(&missing));
        missing = key;
        missing.dnssec = .requested;
        @memset(bank.entries.items(.fingerprint), missing.fingerprint());
        try testing.expectEqual(null, bank.find(&missing));
        for (bank.entries.items(.key), bank.entries.items(.fingerprint)) |*stored, *fingerprint| {
            fingerprint.* = stored.fingerprint();
        }
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
    }
}

// SPEC §1.3: the stdlib allocation is the sum of columns, not the padded Entry size or RSS.
test "cache dense metadata byte budget matches actual allocations" {
    var allocator = testing.FailingAllocator.init(testing.allocator, .{});
    var cache: f.cache.Cache = undefined;
    try cache.init(allocator.allocator(), &f.zone);
    defer cache.deinit();
    const bytes = std.MultiArrayList(f.cache.Entry).capacityInBytes(f.zone.cache.?.capacity);
    try testing.expectEqual(2 * bytes + f.zone.cache.?.packet_bytes_max, allocator.allocated_bytes);
    try testing.expect(bytes <= 320 * f.zone.cache.?.capacity);
}
