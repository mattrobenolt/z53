const f = @import("cache_fixture.zig");
const testing = f.testing;
const wire = f.wire;

// SPEC §1.10, §3.7: two startup arrays, one allocation per insert; lookups allocate nothing.
test "cache allocation budget and transactional insertion exhaustion" {
    var allocator = testing.FailingAllocator.init(testing.allocator, .{});
    var fixture: f.Fixture = undefined;
    try fixture.init(allocator.allocator(), &f.zone);
    defer fixture.cache.deinit();
    try testing.expectEqual(@as(usize, 2), allocator.allocations);
    try testing.expect(@sizeOf(f.cache.Entry) <= 320);
    try fixture.response(0x8500);
    try fixture.record(1, .answer, 5, 0);
    _ = try fixture.forward(0);
    try testing.expectEqual(@as(usize, 3), allocator.allocations);
    allocator.fail_index = allocator.alloc_index;
    const held = allocator.allocated_bytes - allocator.freed_bytes;
    for (0..32) |_| {
        try testing.expect((try fixture.lookup(1)) != null);
        try testing.expectEqual(null, try fixture.lookup(5));
        try testing.expectEqual(.stale, (try fixture.failure(5)).answer.source);
    }
    try testing.expect(!allocator.has_induced_failure);
    const result = try fixture.forward(5);
    try testing.expectEqual(.exhausted, result.insertion);
    try testing.expect(allocator.has_induced_failure);
    try testing.expectEqual(held, allocator.allocated_bytes - allocator.freed_bytes);
    try testing.expectEqual(.stale, (try fixture.failure(6)).answer.source);
    try testing.expectEqual(@as(usize, 3), allocator.allocations);
}

// SPEC §1.11, §3.7: each startup allocation failure releases any preceding owned array.
test "cache startup allocation failures roll back" {
    for (0..2) |fail_index| {
        var allocator = testing.FailingAllocator.init(testing.allocator, .{
            .fail_index = fail_index,
        });
        var cache: f.cache.Cache = undefined;
        try testing.expectError(error.OutOfMemory, cache.init(allocator.allocator(), &f.zone));
        try testing.expect(allocator.has_induced_failure);
        try testing.expectEqual(allocator.allocated_bytes, allocator.freed_bytes);
    }
}

// SPEC §3.9: local encoding failure never publishes an entry or becomes transport failure.
test "cache malformed input and short encoding failure leave stale candidate unchanged" {
    var fixture: f.Fixture = undefined;
    try fixture.init(testing.allocator, &f.zone);
    defer fixture.cache.deinit();
    try fixture.response(0x8500);
    try fixture.record(1, .answer, 5, 0);
    _ = try fixture.forward(0);
    const bytes = try fixture.encoder.finish();
    try testing.expectError(error.NoSpace, fixture.cache.forward(
        &fixture.client.request,
        bytes,
        5,
        &fixture.workspace,
        fixture.client.output[0..12],
    ));
    try testing.expectError(error.Truncated, fixture.cache.forward(
        &fixture.client.request,
        bytes[0..10],
        5,
        &fixture.workspace,
        &fixture.client.output,
    ));
    try testing.expectError(error.NoSpace, fixture.cache.terminalFailure(
        &fixture.client.request,
        5,
        &fixture.workspace,
        fixture.client.output[0..12],
    ));
    try testing.expectEqual(null, try fixture.lookup(5));
    try testing.expectEqual(.stale, (try fixture.failure(5)).answer.source);
}

// SPEC §3.9; RFC 2782: 300 compressed SRV targets expand beyond 65535, never cache local SERVFAIL.
test "cache rejects RewriteTooLarge before insertion" {
    var fixture: f.Fixture = undefined;
    try fixture.init(testing.allocator, &f.zone);
    defer fixture.cache.deinit();
    var name: wire.Name = .{};
    name.length = 255;
    var cursor: usize = 0;
    for ([_]u8{ 63, 63, 63, 61 }) |length| {
        name.bytes[cursor] = length;
        cursor += 1;
        @memset(name.bytes[cursor..][0..length], 'a');
        cursor += length;
    }
    name.bytes[cursor] = 0;
    fixture.client.request.name = name;
    try fixture.response(0x8500);
    // Encode the legacy compressed receive layout directly; the normal encoder forbids it.
    for (0..300) |_| {
        try fixture.encoder.bytes(&.{ 0xc0, 0x0c });
        try fixture.encoder.number(u16, 33);
        try fixture.encoder.number(u16, 1);
        try fixture.encoder.number(u32, 60);
        try fixture.encoder.number(u16, 8);
        try fixture.encoder.bytes(&.{ 0, 0, 0, 0, 0, 53, 0xc0, 0x0c });
        fixture.encoder.header.counts[1] += 1;
    }
    try testing.expectError(error.RewriteTooLarge, fixture.forward(0));
    try testing.expectEqual(null, try fixture.lookup(0));
    for (fixture.cache.positive.entries) |entry| try testing.expectEqual(null, entry.bytes);
    for (fixture.cache.denial.entries) |entry| try testing.expectEqual(null, entry.bytes);
}

// SPEC §3.7: capacity-one churn stays within two entry arrays and two packet allocations at peak.
test "cache bounded capacity one churn and zone isolation" {
    var allocator = testing.FailingAllocator.init(testing.allocator, .{});
    var fixture: f.Fixture = undefined;
    var zone = f.zone;
    zone.cache.?.capacity = 1;
    try fixture.init(allocator.allocator(), &zone);
    defer fixture.cache.deinit();
    var isolated: f.cache.Cache = undefined;
    try isolated.init(testing.allocator, &zone);
    defer isolated.deinit();
    for (0..64) |index| {
        try fixture.client.init(if (index % 2 == 0) "one." else "two.", 1, 1);
        try fixture.response(0x8500);
        try fixture.record(1, .answer, 60, 0);
        _ = try fixture.forward(0);
        try testing.expectEqual(@as(usize, 3), allocator.allocations - allocator.deallocations);
        const bound = 2 * @sizeOf(f.cache.Entry) + wire.message_bytes_max;
        try testing.expect(allocator.allocated_bytes - allocator.freed_bytes <= bound);
        try testing.expectEqual(null, try isolated.lookup(
            &fixture.client.request,
            0,
            &fixture.workspace,
            &fixture.client.output,
        ));
    }
}
