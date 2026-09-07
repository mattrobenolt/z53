const std = @import("std");
const f = @import("cache_fixture.zig");
const testing = f.testing;
const capacity = 128;

fn identity(fixture: *f.Fixture, key: u16, id: u16) !void {
    var text: [64]u8 = undefined;
    const name = try std.fmt.bufPrint(&text, "key{d}.stress.example.", .{key / 8});
    try fixture.client.init(name, if (key & 1 == 0) 1 else 255, if (key & 2 == 0) 1 else 3);
    if (key & 4 != 0) try fixture.client.edns(&.{});
    fixture.client.query.header.id = id;
}

fn insert(fixture: *f.Fixture, bank: enum { positive, denial }) !void {
    try fixture.response(if (bank == .positive) 0x8500 else 0x8503);
    if (bank == .positive) {
        try fixture.record(1, .answer, 60, 0);
    } else try fixture.record(6, .authority, 60, 60);
    const result = try fixture.forward(100);
    try testing.expectEqual(.stored, result.insertion);
    try testing.expectEqual(.forward, result.answer.source);
}

fn hit(fixture: *f.Fixture, now_s: u64, rcode: u16) !void {
    const result = (try fixture.lookup(now_s)) orelse return error.UnexpectedMiss;
    try testing.expectEqual(.cache, result.source);
    try fixture.ttl(&result, @intCast(160 - now_s));
    const packet = &fixture.client.response;
    try testing.expectEqual(fixture.client.query.header.id, packet.header.id);
    try testing.expectEqual(rcode, packet.header.bits & 15);
    var cursor: usize = 12;
    const question = try packet.readQuestion(&cursor);
    var name: f.wire.Name = undefined;
    try packet.name(&name, question.name);
    try testing.expectEqualSlices(u8, fixture.client.request.name.wire(), name.wire());
    try testing.expectEqual(fixture.client.request.kind, question.kind);
    try testing.expectEqual(fixture.client.request.class, question.class);
    try testing.expectEqual(fixture.client.query.opt != null, packet.opt != null);
    if (packet.opt) |index| try testing.expectEqual(0x8000, packet.records[index].ttl_s);
    const record = packet.records[0];
    if (rcode == 0)
        try testing.expectEqualSlices(
            u8,
            &.{ 192, 0, 2, 1 },
            result.bytes[record.data_start..record.data_end],
        );
}

// SPEC §§1.3, 3.7, RFC 6891 §6.1.4: full-capacity mixed keys preserve LRU, IDs, TTLs, and DO.
test "cache stress full capacity mixed keys and repeated LRU churn without hit allocation" {
    var allocator = testing.FailingAllocator.init(testing.allocator, .{});
    var fixture: f.Fixture = undefined;
    var zone = f.zone;
    zone.cache = .{ .capacity = capacity };
    try fixture.init(allocator.allocator(), &zone);
    defer fixture.cache.deinit();
    // The independent model stores oldest first, without the cache's intrusive links.
    var order: [capacity]u16 = undefined;
    for (&order, 0..) |*key, index| {
        key.* = @intCast(index);
        try identity(&fixture, key.*, @intCast(index));
        try insert(&fixture, .positive);
    }
    for (0..16) |round| {
        const allocations = allocator.alloc_index;
        allocator.fail_index = allocations;
        for (0..32) |probe| {
            const position = (round * 17 + probe * 31) % capacity;
            const key = order[position];
            try identity(&fixture, key, @intCast(1000 + round * 32 + probe));
            try hit(&fixture, 101 + round, 0);
            @memmove(order[position .. capacity - 1], order[position + 1 ..]);
            order[capacity - 1] = key;
        }
        try testing.expectEqual(allocations, allocator.alloc_index);
        try testing.expect(!allocator.has_induced_failure);
        allocator.fail_index = std.math.maxInt(usize);
        const evicted = order[0];
        const next: u16 = @intCast(capacity + round);
        try identity(&fixture, next, @intCast(2000 + round));
        try insert(&fixture, .positive);
        @memmove(order[0 .. capacity - 1], order[1..]);
        order[capacity - 1] = next;
        try identity(&fixture, evicted, 3000);
        try testing.expectEqual(null, try fixture.lookup(101 + round));
    }
    for (order) |key| {
        try identity(&fixture, key, key + 4000);
        try hit(&fixture, 117, 0);
    }
}

// SPEC §3.7: cross-bank replacement at capacity removes old keys without shadow entries.
test "cache stress full positive and denial banks replace every entry twice" {
    var fixture: f.Fixture = undefined;
    var zone = f.zone;
    zone.cache = .{ .capacity = capacity };
    try fixture.init(testing.allocator, &zone);
    defer fixture.cache.deinit();
    for (0..capacity * 2) |index| {
        try identity(&fixture, @intCast(index), @intCast(index));
        try insert(&fixture, if (index < capacity) .positive else .denial);
    }
    for (0..capacity) |index| {
        try identity(&fixture, @intCast(index), @intCast(1000 + index));
        try hit(&fixture, 101, 0);
        try insert(&fixture, .denial);
        try hit(&fixture, 102, 3);
        try identity(&fixture, @intCast(capacity + index), 2000);
        try testing.expectEqual(null, try fixture.lookup(102));
    }
    for (fixture.cache.positive.entries.items(.bytes)) |bytes| try testing.expectEqual(null, bytes);
    for (0..capacity) |index| {
        try identity(&fixture, @intCast(index), @intCast(3000 + index));
        try insert(&fixture, .positive);
        try hit(&fixture, 103, 0);
    }
    for (fixture.cache.denial.entries.items(.bytes)) |bytes| try testing.expectEqual(null, bytes);
}
