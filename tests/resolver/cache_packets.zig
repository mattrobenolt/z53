const std = @import("std");
const f = @import("cache_fixture.zig");
const testing = std.testing;
const packets = f.cache.packets;

// SPEC §§1.3, 3.7: every class boundary supports allocate/free/reuse without backing growth.
test "cache packet classes include full DNS size and reuse every boundary" {
    var allocator = testing.FailingAllocator.init(testing.allocator, .{});
    var storage: packets.Storage = undefined;
    try storage.init(allocator.allocator(), 1024 * 1024);
    defer storage.deinit(allocator.allocator());
    allocator.fail_index = allocator.alloc_index;
    for (packets.sizes, 0..) |size, index| {
        const low = if (index == 0) 1 else packets.sizes[index - 1] + 1;
        const high = @min(size, f.wire.message_bytes_max);
        for ([_]u32{ low, high }) |length| {
            try testing.expectEqual(index, packets.class(length));
            const first = try storage.create(length);
            @memset(first, 42);
            const address = first.ptr;
            const used = storage.fixed.end_index;
            storage.destroy(first, @intCast(index));
            const second = try storage.create(length);
            try testing.expectEqual(address, second.ptr);
            try testing.expectEqual(used, storage.fixed.end_index);
            try testing.expectEqual(length, storage.live_bytes);
            try testing.expectEqual(size, storage.live_class_bytes);
            storage.destroy(second, @intCast(index));
            try testing.expectEqual(0, storage.live_bytes);
            try testing.expectEqual(0, storage.live_class_bytes);
        }
    }
    try testing.expect(!allocator.has_induced_failure);
    try testing.expectEqual(1, allocator.allocations);
    try testing.expect(storage.fixed.end_index <= storage.fixed.buffer.len);
}

fn fill(storage: *packets.Storage) !void {
    // The minimum block size bounds successful allocations by backing_bytes / 64.
    for (0..storage.fixed.buffer.len / 64 + 1) |_| {
        _ = storage.create(64) catch return;
    }
    return error.UnboundedStorage;
}

// SPEC §3.7: free blocks remain reusable, but classes do not borrow each other's free lists.
test "cache packet exhaustion and class pressure retain bounded reuse" {
    var storage: packets.Storage = undefined;
    try storage.init(testing.allocator, 64 * 1024);
    defer storage.deinit(testing.allocator);
    const first = try storage.create(64);
    const address = first.ptr;
    try fill(&storage);
    try testing.expectError(error.OutOfMemory, storage.create(64));
    storage.destroy(first, 0);
    try testing.expectError(error.OutOfMemory, storage.create(65535));
    const reused = try storage.create(64);
    try testing.expectEqual(address, reused.ptr);
    storage.destroy(reused, 0);
}

// SPEC §§3.7, 3.9: byte exhaustion returns the valid answer and preserves the stale packet.
test "cache packet pressure preserves stale data and rejects destructive class replacement" {
    var allocator = testing.FailingAllocator.init(testing.allocator, .{});
    var fixture: f.Fixture = undefined;
    var zone = f.zone;
    zone.cache.?.packet_bytes_max = 64 * 1024;
    try fixture.init(allocator.allocator(), &zone);
    defer fixture.cache.deinit();
    allocator.fail_index = allocator.alloc_index;
    try fixture.response(0x8500);
    try fixture.record(1, .answer, 5, 0);
    try testing.expectEqual(.stored, (try fixture.forward(0)).insertion);
    const old = fixture.cache.positive.entries.items(.bytes)[0].?;
    try fill(&fixture.cache.packet_storage);
    try fixture.response(0x8503);
    for (0..3) |_| try fixture.record(6, .authority, 60, 60);
    const denied = try fixture.forward(5);
    try testing.expectEqual(.exhausted, denied.insertion);
    try testing.expectEqual(.forward, denied.answer.source);
    try fixture.client.response.parse(denied.answer.bytes);
    try testing.expectEqual(3, fixture.client.response.header.bits & 15);
    try testing.expectEqual(old.ptr, fixture.cache.positive.entries.items(.bytes)[0].?.ptr);
    try testing.expectEqual(null, fixture.cache.denial.first);
    try testing.expectEqual(.stale, (try fixture.failure(5)).answer.source);
    try testing.expect(!allocator.has_induced_failure);
}

// SPEC §3.7: same-class refresh and cross-bank transfer succeed even when all blocks are busy.
test "cache full packet arena refresh eviction and cross bank transfer allocate nothing" {
    var allocator = testing.FailingAllocator.init(testing.allocator, .{});
    var fixture: f.Fixture = undefined;
    var zone = f.zone;
    zone.cache.?.capacity = 1;
    zone.cache.?.packet_bytes_max = 64 * 1024;
    try fixture.init(allocator.allocator(), &zone);
    defer fixture.cache.deinit();
    allocator.fail_index = allocator.alloc_index;
    try fixture.response(0x8500);
    try fixture.record(1, .answer, 5, 0);
    _ = try fixture.forward(0);
    const address = fixture.cache.positive.entries.items(.bytes)[0].?.ptr;
    try fill(&fixture.cache.packet_storage);
    for (0..32) |index| {
        try fixture.response(0x8500);
        try fixture.record(1, .answer, 5, 0);
        try testing.expectEqual(.stored, (try fixture.forward(index)).insertion);
        try testing.expectEqual(address, fixture.cache.positive.entries.items(.bytes)[0].?.ptr);
        try testing.expect((try fixture.lookup(index)) != null);
    }
    // SERVFAIL has the same class and transfers this key into the empty denial bank.
    try fixture.response(0x8502);
    try testing.expectEqual(.stored, (try fixture.forward(32)).insertion);
    try testing.expectEqual(null, fixture.cache.positive.first);
    try testing.expectEqual(address, fixture.cache.denial.entries.items(.bytes)[0].?.ptr);
    try fixture.response(0x8500);
    try fixture.record(1, .answer, 5, 0);
    try testing.expectEqual(.stored, (try fixture.forward(33)).insertion);
    try testing.expectEqual(null, fixture.cache.denial.first);
    try fixture.client.init("evicted.", 1, 1);
    try fixture.response(0x8500);
    try fixture.record(1, .answer, 5, 0);
    try testing.expectEqual(.stored, (try fixture.forward(34)).insertion);
    try testing.expectEqual(address, fixture.cache.positive.entries.items(.bytes)[0].?.ptr);
    fixture.cache.positive.remove(&fixture.cache.packet_storage, 0);
    try testing.expectEqual(.stored, (try fixture.forward(35)).insertion);
    try testing.expectEqual(address, fixture.cache.positive.entries.items(.bytes)[0].?.ptr);
    try testing.expect(!allocator.has_induced_failure);
    try testing.expectEqual(3, allocator.allocations);
    try testing.expectEqual(0, allocator.deallocations);
    try testing.expectEqual(0, allocator.resize_index);
}

// SPEC §3.7: byte pressure cannot raid unrelated entries in the other bank.
test "cache class pressure preserves both bank victims and their LRU links" {
    var fixture: f.Fixture = undefined;
    var zone = f.zone;
    zone.cache.?.capacity = 1;
    zone.cache.?.packet_bytes_max = 64 * 1024;
    try fixture.init(testing.allocator, &zone);
    defer fixture.cache.deinit();
    try fixture.response(0x8500);
    try fixture.record(1, .answer, 5, 0);
    _ = try fixture.forward(0);
    const positive = fixture.cache.positive.entries.items(.bytes)[0].?;
    try fixture.client.init("denied.example.", 1, 1);
    try fixture.response(0x8503);
    try fixture.record(6, .authority, 5, 5);
    _ = try fixture.forward(0);
    const denial = fixture.cache.denial.entries.items(.bytes)[0].?;
    try fill(&fixture.cache.packet_storage);
    // Drain the already reserved 128-byte class arena as well as the shared backing.
    for (0..1025) |_| {
        _ = fixture.cache.packet_storage.create(128) catch break;
    } else return error.UnboundedStorage;
    try fixture.client.init("replacement.example.", 1, 1);
    try fixture.response(0x8500);
    for (0..3) |_| try fixture.record(1, .answer, 60, 0);
    try testing.expectEqual(.exhausted, (try fixture.forward(5)).insertion);
    try testing.expectEqual(positive.ptr, fixture.cache.positive.entries.items(.bytes)[0].?.ptr);
    try testing.expectEqual(denial.ptr, fixture.cache.denial.entries.items(.bytes)[0].?.ptr);
    const banks = [_]*@TypeOf(fixture.cache.positive){
        &fixture.cache.positive,
        &fixture.cache.denial,
    };
    for (banks) |bank| {
        try testing.expectEqual(0, bank.first.?);
        try testing.expectEqual(0, bank.last.?);
        try testing.expectEqual(null, bank.entries.items(.previous)[0]);
        try testing.expectEqual(null, bank.entries.items(.next)[0]);
    }
    try fixture.client.init("example.", 1, 1);
    try testing.expectEqual(.stale, (try fixture.failure(5)).answer.source);
    try fixture.client.init("denied.example.", 1, 1);
    try testing.expectEqual(.stale, (try fixture.failure(5)).answer.source);
}

// SPEC §§3.7, 3.9: the full 65535-byte DNS message survives storage and cache delivery.
test "cache packet pool stores and serves the maximum DNS message" {
    var allocator = testing.FailingAllocator.init(testing.allocator, .{});
    var fixture: f.Fixture = undefined;
    try fixture.init(allocator.allocator(), &f.zone);
    defer fixture.cache.deinit();
    allocator.fail_index = allocator.alloc_index;
    try fixture.client.init(".", 65280, 1);
    try fixture.response(0x8500);
    const offset = try fixture.encoder.beginRecord(&fixture.client.request.name, &.{
        .owner = 0,
        .kind = 65280,
        .class = 1,
        .ttl_s = 60,
        .data_start = 0,
        .data_end = 0,
        .section = .answer,
    });
    const padding: [f.wire.message_bytes_max]u8 = @splat(0);
    try fixture.encoder.bytes(padding[0 .. padding.len - fixture.encoder.cursor]);
    fixture.encoder.endRecord(offset);
    const result = try fixture.forward(0);
    try testing.expectEqual(.stored, result.insertion);
    try testing.expectEqual(65535, result.answer.bytes.len);
    try testing.expectEqual(65535, fixture.cache.packet_storage.live_bytes);
    try testing.expectEqual(65536, fixture.cache.packet_storage.live_class_bytes);
    const hit = (try fixture.lookup(1)).?;
    try testing.expectEqual(65535, hit.bytes.len);
    try fixture.ttl(&hit, 59);
    try testing.expect(!allocator.has_induced_failure);
}

// SPEC §§1.3, 5.1: a disabled cache reserves no packet or bank storage.
test "disabled cache allocates no storage" {
    var allocator = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    var zone = f.zone;
    zone.cache = null;
    var cache: f.cache.Cache = undefined;
    try cache.init(allocator.allocator(), &zone);
    defer cache.deinit();
    try testing.expectEqual(0, allocator.allocations);
    try testing.expectEqual(0, cache.packet_storage.fixed.buffer.len);
    try testing.expect(!allocator.has_induced_failure);
}
