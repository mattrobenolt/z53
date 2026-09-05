const std = @import("std");
const runtime = @import("runtime");
const testing = std.testing;
const linux = std.os.linux;
const wire = runtime.pipeline.wire;

test {
    _ = @import("runtime_transport.zig");
}

// SPEC §1.1: fixed runtime storage excludes separately bounded zone cache and hosts tables.
test "runtime fixed storage budget" {
    try testing.expect(@sizeOf(runtime.Runtime) <= 32 * 1024 * 1024);
    try testing.expectEqual(128, runtime.tcp.clients_max);
    try testing.expectEqual(64, runtime.proctor.buffers_max);
    try testing.expectEqual(225, runtime.proctor.operations_max);
}

// SPEC §1: cancellation and target completion jointly release ownership, in either order.
test "completion generations and cancellation barriers" {
    var owner: runtime.proctor.Ownership = .{};
    const first = try owner.arm(4);
    try owner.complete(first, .more);
    owner.cancel();
    try owner.complete(first, .terminal);
    try testing.expectEqual(.target_done, owner.state);
    try owner.complete(first, .cancellation);
    const second = try owner.arm(4);
    try testing.expectError(error.InvalidCompletion, owner.complete(first, .terminal));
    owner.cancel();
    try owner.complete(second, .cancellation);
    try testing.expectEqual(.cancel_done, owner.state);
    try owner.complete(second, .more);
    try owner.complete(second, .terminal);
    try testing.expectEqual(.idle, owner.state);
    owner.generation = std.math.maxInt(u31);
    try testing.expectError(error.GenerationExhausted, owner.arm(4));
}

// RFC 1035 §4.2.2: fragmented framing, partial sends, and repeated queries are bounded.
test "TCP partial framing and repeated responses" {
    const client = try testing.allocator.create(runtime.tcp.Client);
    defer testing.allocator.destroy(client);
    client.reset();
    client.input[0..2].* = .{ 0, 12 };
    try testing.expectEqual(null, try client.received(1));
    try testing.expectEqual(null, try client.received(1));
    try testing.expectEqual(null, try client.received(5));
    try testing.expectEqual(@as(usize, 12), (try client.received(7)).?.len);
    client.respond(12);
    try client.sent(3);
    try testing.expectEqual(.response, client.phase);
    try client.sent(11);
    try testing.expectEqual(.prefix, client.phase);
    client.input[0..2].* = .{ 0, 11 };
    try testing.expectError(error.InvalidFrame, client.received(2));
    client.nextQuery();
    try testing.expectError(error.Closed, client.received(0));
    try testing.expectError(error.InvalidFrame, client.received(3));
}

// SPEC §1: mandatory ring setup, provided buffers, and cancellation execute on Linux.
test "native ring setup registered files and cancellation" {
    const proctor = try testing.allocator.create(runtime.proctor.Proctor);
    defer testing.allocator.destroy(proctor);
    try proctor.init();
    defer proctor.deinit();
    try proctor.ring.register_files_sparse(160);
    var interval: linux.kernel_timespec = .{ .sec = 60, .nsec = 0 };
    const token = try proctor.arm(32);
    _ = try proctor.ring.timeout(token, &interval, 0, 0);
    _ = try proctor.ring.submit();
    try proctor.stop();
    var completions: u8 = 0;
    while (proctor.pending()) {
        _ = try proctor.next();
        completions += 1;
        try testing.expect(completions <= 2);
    }
    try testing.expectEqual(2, completions);
}

// SPEC §1: teardown also handles startup before the file table was registered.
test "native proctor teardown without registered files" {
    const proctor = try testing.allocator.create(runtime.proctor.Proctor);
    defer testing.allocator.destroy(proctor);
    try proctor.init();
    proctor.deinit();
}

// SPEC §1: actual io_uring_setup failure is a startup error, with no probe or fallback.
test "native setup failure under descriptor quota" {
    const proctor = try testing.allocator.create(runtime.proctor.Proctor);
    defer testing.allocator.destroy(proctor);
    var previous: linux.rlimit = undefined;
    try testing.expectEqual(.SUCCESS, linux.errno(linux.prlimit(0, .NOFILE, null, &previous)));
    const limited: linux.rlimit = .{ .cur = 0, .max = previous.max };
    try testing.expectEqual(.SUCCESS, linux.errno(linux.prlimit(0, .NOFILE, &limited, null)));
    defer {
        const restored = linux.prlimit(0, .NOFILE, &previous, null);
        testing.expectEqual(.SUCCESS, linux.errno(restored)) catch
            @panic("failed to restore descriptor quota");
    }
    try testing.expectError(error.SetupFailed, proctor.init());
}

// SPEC §3.5: enabled hosts loads initially even when its periodic check is disabled.
test "initial hosts failure and startup allocation rollback" {
    const pipeline = try testing.allocator.create(runtime.pipeline.Pipeline);
    defer testing.allocator.destroy(pipeline);
    var zones = [_]runtime.pipeline.resolver.config.Zone{.{
        .suffix = ".",
        .upstreams = &.{.{ .address = "127.0.0.1:1" }},
        .cache = .{ .capacity = 1 },
        .hosts = .{ .path = "/nonexistent-z53-test/hosts", .reload_s = 0 },
    }};
    const settings: runtime.pipeline.resolver.config.Config = .{ .zones = &zones };
    try testing.expectError(
        error.HostsLoadFailed,
        pipeline.init(testing.allocator, testing.io, &settings),
    );
    for (0..5) |index| {
        var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = index });
        try testing.expectError(
            error.OutOfMemory,
            pipeline.init(failing.allocator(), testing.io, &settings),
        );
    }
}

// SPEC §3.9: truncated recvmsg payloads never become partial DNS requests.
test "UDP recvmsg metadata bounds" {
    var bytes: [runtime.proctor.buffer_bytes]u8 = @splat(0);
    var header: linux.io_uring_recvmsg_out = .{
        .namelen = 16,
        .controllen = 0,
        .payloadlen = 12,
        .flags = 0,
    };
    @memcpy(bytes[0..16], std.mem.asBytes(&header));
    const family: linux.sa_family_t = linux.AF.INET;
    @memcpy(bytes[16..18], std.mem.asBytes(&family));
    try testing.expectEqual(@as(usize, 12), (try runtime.udp.decode(bytes[0..156])).payload.len);
    try testing.expectError(error.InvalidDatagram, runtime.udp.decode(bytes[0..155]));
    header.flags = linux.MSG.TRUNC;
    @memcpy(bytes[0..16], std.mem.asBytes(&header));
    try testing.expectError(error.InvalidDatagram, runtime.udp.decode(bytes[0..156]));
}

// RFC 768; RFC 791 §3.1; RFC 8200 §3; SPEC §3.9: fixed-header UDP payload ceilings.
test "IPv4 and IPv6 UDP exact caps and complete RRset truncation" {
    const fixture = try testing.allocator.create(struct {
        encoder: wire.Encoder,
        rewrite: wire.rewrite.Workspace,
        packet: wire.Packet,
        input: [65535]u8,
        output: [65535]u8,
        data: [65535]u8,
    });
    defer testing.allocator.destroy(fixture);
    @memset(&fixture.data, 0);
    var name: wire.Name = undefined;
    try name.fromText(".");
    for ([_]runtime.udp.Family{ .ipv4, .ipv6 }) |family| {
        const cap: u16 = if (family == .ipv4) 65507 else 65527;
        try testing.expectEqual(@as(u16, 512), runtime.udp.limit(0, family));
        try testing.expectEqual(cap, runtime.udp.limit(cap, family));
        try testing.expectEqual(cap, runtime.udp.limit(cap + 1, family));
        for (0..2) |extra| {
            try fixture.encoder.init(&fixture.input, &.{ .bits = 0x8000 });
            try fixture.encoder.question(&name, 65400, 1);
            const record: wire.Record = .{
                .owner = 0,
                .kind = 65400,
                .class = 1,
                .ttl_s = 30,
                .data_start = 0,
                .data_end = 0,
                .section = .answer,
            };
            const start = try fixture.encoder.beginRecord(&name, &record);
            try fixture.encoder.bytes(fixture.data[0 .. @as(usize, cap) - 39 + extra]);
            fixture.encoder.endRecord(start);
            try wire.rewrite.writeOpt(&fixture.encoder, &.{ .payload_bytes = 65535 });
            const input = try fixture.encoder.finish();
            try testing.expectEqual(@as(usize, cap) + extra, input.len);
            try fixture.packet.parse(input);
            const settings: wire.rewrite.Settings = .{
                .limit = .{ .udp = runtime.udp.limit(65535, family) },
            };
            const output = try fixture.rewrite.rewrite(&fixture.packet, &fixture.output, &settings);
            try testing.expect(output.len <= cap);
            try fixture.packet.parse(output);
            try testing.expectEqual(extra == 1, fixture.packet.header.has(.truncated));
            try testing.expectEqual(1 - extra, fixture.packet.header.counts[1]);
            try testing.expectEqual(65535, fixture.packet.records[fixture.packet.opt.?].class);
        }
    }
}

// SPEC §3.2: unresolved forwarding is a local failure, never a stale/cache insertion.
test "local pipeline and explicit unresolved forwarding" {
    const pipeline = try testing.allocator.create(runtime.pipeline.Pipeline);
    defer testing.allocator.destroy(pipeline);
    var zones = [_]runtime.pipeline.resolver.config.Zone{.{
        .suffix = ".",
        .upstreams = &.{.{ .address = "127.0.0.1:1" }},
        .cache = .{ .capacity = 1 },
    }};
    const settings: runtime.pipeline.resolver.config.Config = .{ .zones = &zones };
    var allocator = testing.FailingAllocator.init(testing.allocator, .{});
    try pipeline.init(allocator.allocator(), testing.io, &settings);
    defer pipeline.deinit();
    const allocations = allocator.alloc_index;
    allocator.fail_index = allocations;
    var input: [512]u8 = undefined;
    var output: [65535]u8 = undefined;
    var encoder: wire.Encoder = undefined;
    var name: wire.Name = undefined;
    try name.fromText("localhost.");
    try encoder.init(&input, &.{ .id = 42, .bits = 0x100 });
    try encoder.question(&name, 1, 1);
    const local = (try pipeline.answer(try encoder.finish(), &output, .{ .udp = .ipv4 }, 0)).?;
    try testing.expectEqual(.rfc6761, local.source);
    try testing.expectEqual(0x8500, (try wire.Header.decode(local.bytes)).bits);
    try name.fromText("missing.example.");
    try encoder.init(&input, &.{ .id = 43 });
    try encoder.question(&name, 1, 1);
    const missing = (try pipeline.answer(try encoder.finish(), &output, .tcp, 0)).?;
    try testing.expectEqual(.servfail, missing.source);
    try testing.expectEqual(2, (try wire.Header.decode(missing.bytes)).bits & 15);
    try testing.expectEqual(null, pipeline.zones[0].cache.positive.entries[0].bytes);
    try testing.expectEqual(null, pipeline.zones[0].cache.denial.entries[0].bytes);
    try testing.expectEqual(allocations, allocator.alloc_index);
    try testing.expect(!allocator.has_induced_failure);
}
