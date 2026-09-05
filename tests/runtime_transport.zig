const std = @import("std");
const runtime = @import("runtime");
const testing = std.testing;
const linux = std.os.linux;
const wire = runtime.pipeline.wire;

const Harness = struct {
    service: *runtime.Runtime,
    settings: runtime.pipeline.resolver.config.Config,
    zones: [1]runtime.pipeline.resolver.config.Zone,
    listen: [1][]const u8,
    text: [64]u8,
    address: runtime.address.Address,

    fn init(self: *Harness) !void {
        try self.address.parse("127.0.0.1:1");
        const ip: *linux.sockaddr.in = @ptrCast(&self.address.storage);
        ip.port = 0;
        const reservation = try self.address.bind(linux.SOCK.STREAM);
        defer _ = linux.close(reservation);
        try testing.expectEqual(.SUCCESS, linux.errno(linux.getsockname(
            reservation,
            @ptrCast(&self.address.storage),
            &self.address.length,
        )));
        self.listen[0] = try std.fmt.bufPrint(&self.text, "127.0.0.1:{d}", .{
            std.mem.bigToNative(u16, ip.port),
        });
        self.zones = .{.{
            .suffix = ".",
            .cache = null,
            .nodata = &.{.AAAA},
            .upstreams = &.{.{ .address = "127.0.0.1:1" }},
        }};
        self.settings = .{ .listen = &self.listen, .zones = &self.zones };
        self.service = try testing.allocator.create(runtime.Runtime);
    }

    fn start(self: *Harness) !void {
        errdefer testing.allocator.destroy(self.service);
        try self.service.init(testing.allocator, testing.io, &self.settings);
    }

    fn deinit(self: *Harness) void {
        self.service.deinit();
        testing.allocator.destroy(self.service);
        self.* = undefined;
    }

    fn socket(self: *Harness, kind: u32) !linux.fd_t {
        const result = linux.socket(linux.AF.INET, kind | linux.SOCK.NONBLOCK, 0);
        try testing.expectEqual(.SUCCESS, linux.errno(result));
        const descriptor: linux.fd_t = @intCast(result);
        errdefer _ = linux.close(descriptor);
        switch (linux.errno(linux.connect(
            descriptor,
            @ptrCast(&self.address.storage),
            self.address.length,
        ))) {
            .SUCCESS, .INPROGRESS => {},
            else => return error.ConnectFailed,
        }
        return descriptor;
    }

    fn receive(self: *Harness, descriptor: linux.fd_t, output: []u8) !usize {
        for (0..64) |_| {
            const result = linux.recvfrom(descriptor, output.ptr, output.len, 0, null, null);
            switch (linux.errno(result)) {
                .SUCCESS => return result,
                .AGAIN => try testing.expect(try self.service.step()),
                else => return error.ReceiveFailed,
            }
        }
        return error.TestDeadline;
    }

    fn frame(self: *Harness, descriptor: linux.fd_t, output: []u8) ![]const u8 {
        var length: usize = 0;
        for (0..64) |_| {
            length += try self.receive(descriptor, output[length..]);
            if (try wire.frame(output[0..length])) |value| return value.message;
        }
        return error.TestDeadline;
    }

    fn stop(self: *Harness) !void {
        try self.service.stop();
        for (0..runtime.proctor.operations_max * 3) |_| {
            if (!try self.service.step()) return;
        }
        return error.CancellationDidNotDrain;
    }
};

fn send(descriptor: linux.fd_t, bytes: []const u8) !void {
    const result = linux.sendto(descriptor, bytes.ptr, bytes.len, linux.MSG.NOSIGNAL, null, 0);
    try testing.expectEqual(.SUCCESS, linux.errno(result));
    try testing.expectEqual(bytes.len, result);
}

fn query(output: []u8) ![]const u8 {
    return queryName(output, "localhost.", 1);
}

fn queryName(output: []u8, text: []const u8, kind: u16) ![]const u8 {
    var encoder: wire.Encoder = undefined;
    var name: wire.Name = undefined;
    try name.fromText(text);
    try encoder.init(output, &.{ .id = 345, .bits = 0x100 });
    try encoder.question(&name, kind, 1);
    return encoder.finish();
}

// SPEC §1 and §3.9: real multishot UDP and direct ACCEPT serve local loopback queries.
test "native UDP and TCP repeated queries and cancellation" {
    var harness: Harness = undefined;
    try harness.init();
    try harness.start();
    defer harness.deinit();
    const datagram = try harness.socket(linux.SOCK.DGRAM);
    defer _ = linux.close(datagram);
    var input: [512]u8 = undefined;
    var output: [65537]u8 = undefined;
    const request = try query(input[2..]);
    for (0..3) |_| {
        try send(datagram, request);
        const length = try harness.receive(datagram, &output);
        const header = try wire.Header.decode(output[0..length]);
        try testing.expectEqual(345, header.id);
        try testing.expectEqual(1, header.counts[1]);
    }
    const stream = try harness.socket(linux.SOCK.STREAM);
    defer _ = linux.close(stream);
    try wire.framePrefix(&input, request.len);
    // Split the prefix, then send two coalesced requests on the same connection.
    try send(stream, input[0..1]);
    try testing.expect(try harness.service.step());
    try send(stream, input[1 .. request.len + 2]);
    _ = try harness.frame(stream, &output);
    try send(stream, input[0 .. request.len + 2]);
    try send(stream, input[0 .. request.len + 2]);
    for (0..2) |_| {
        const response = try harness.frame(stream, &output);
        try testing.expectEqual(345, (try wire.Header.decode(response)).id);
    }
    try harness.stop();
    try testing.expect(!harness.service.proctor.pending());
}

// SPEC §1.8 and §8.2: teardown permits immediate same-port restarts, including TCP TIME_WAIT.
test "native immediate repeated restart after server TCP close" {
    var harness: Harness = undefined;
    try harness.init();
    defer testing.allocator.destroy(harness.service);
    for (0..16) |index| {
        try harness.service.init(testing.allocator, testing.io, &harness.settings);
        defer harness.service.deinit();
        try restartExchange(&harness);
        // Exercise both drained shutdown and cancellation with outstanding listener work.
        if (index % 2 == 0) try harness.stop();
    }
}

fn restartExchange(harness: *Harness) !void {
    const datagram = try harness.socket(linux.SOCK.DGRAM);
    defer _ = linux.close(datagram);
    const stream = try harness.socket(linux.SOCK.STREAM);
    defer _ = linux.close(stream);
    var input: [512]u8 = undefined;
    var output: [512]u8 = undefined;
    const request = try query(input[2..]);
    try send(datagram, request);
    const length = try harness.receive(datagram, &output);
    try testing.expectEqual(345, (try wire.Header.decode(output[0..length])).id);
    try wire.framePrefix(&input, request.len);
    try send(stream, input[0 .. request.len + 2]);
    const response = try harness.frame(stream, &output);
    try testing.expectEqual(345, (try wire.Header.decode(response)).id);
    // RFC 1035 §4.2.2: an invalid frame makes the server the active closer.
    try send(stream, &.{ 0, 0 });
    try testing.expectEqual(0, try harness.receive(stream, &output));
}

// SPEC §1: rollback releases already-registered listeners and an unregistered socket.
test "native immediate repeated restart after partial initialization" {
    var harness: Harness = undefined;
    try harness.init();
    defer testing.allocator.destroy(harness.service);
    var other: Harness = undefined;
    try other.init();
    defer testing.allocator.destroy(other.service);
    const occupied = try other.address.bind(linux.SOCK.STREAM);
    defer _ = linux.close(occupied);
    const listeners = [_][]const u8{ harness.listen[0], other.listen[0] };
    var settings = harness.settings;
    settings.listen = &listeners;
    for (0..16) |_| {
        try testing.expectError(
            error.BindFailed,
            harness.service.init(testing.allocator, testing.io, &settings),
        );
        // The second UDP socket was opened before its TCP bind failed.
        const released = try other.address.bind(linux.SOCK.DGRAM);
        _ = linux.close(released);
        try harness.service.init(testing.allocator, testing.io, &harness.settings);
        harness.service.deinit();
    }
}

// SPEC §1: fixed UDP response exhaustion drops input and releases its provided buffer.
test "native UDP response pool exhaustion and recovery" {
    var harness: Harness = undefined;
    try harness.init();
    try harness.start();
    defer harness.deinit();
    const descriptor = try harness.socket(linux.SOCK.DGRAM);
    defer _ = linux.close(descriptor);
    var input: [512]u8 = undefined;
    var output: [512]u8 = undefined;
    const request = try query(&input);
    for (&harness.service.responses) |*response| response.state = .sending;
    try send(descriptor, request);
    try testing.expect(try harness.service.step());
    const dropped = linux.recvfrom(descriptor, &output, output.len, 0, null, null);
    try testing.expectEqual(.AGAIN, linux.errno(dropped));
    for (&harness.service.responses) |*response| response.state = .free;
    // More than one complete provided-ring cycle proves reuse after the dropped request.
    for (0..runtime.proctor.buffers_max + 1) |_| {
        try send(descriptor, request);
        _ = try harness.receive(descriptor, &output);
    }
    try harness.stop();
}

fn hostsFile(directory: std.Io.Dir, source: []const u8, seconds: i64) !void {
    try directory.writeFile(testing.io, .{ .sub_path = "hosts", .data = source });
    const file = try directory.openFile(testing.io, "hosts", .{});
    defer file.close(testing.io);
    try file.setTimestamps(testing.io, .{
        .modify_timestamp = .{ .new = .fromNanoseconds(@as(i96, seconds) * std.time.ns_per_s) },
    });
}

// SPEC §3.5: real io_uring timers retry failed reloads and zero disables later checks.
test "native hosts reload timer failure retry and disabled checks" {
    var temporary = testing.tmpDir(.{});
    defer temporary.cleanup();
    var path_buffer: [128]u8 = undefined;
    const path = try std.fmt.bufPrint(
        &path_buffer,
        ".zig-cache/tmp/{s}/hosts",
        .{temporary.sub_path},
    );
    try hostsFile(temporary.dir, "192.0.2.1 old\n", 100);
    var harness: Harness = undefined;
    try harness.init();
    harness.zones[0].hosts = .{ .path = path, .reload_s = 1 };
    try harness.start();
    defer harness.deinit();
    const store = &harness.service.pipeline.zones[0].hosts.?;
    try testing.expectEqual(@as(u16, 1), store.table().count);
    try temporary.dir.deleteFile(testing.io, "hosts");
    try testing.expect(try harness.service.step());
    try testing.expectEqual(@as(?i128, 100 * std.time.ns_per_s), store.mtime);
    try hostsFile(temporary.dir, "", 101);
    try testing.expect(try harness.service.step());
    try testing.expectEqual(@as(u16, 0), store.table().count);
    try testing.expectEqual(@as(?i128, 101 * std.time.ns_per_s), store.mtime);
    harness.zones[0].hosts.?.reload_s = 0;
    try hostsFile(temporary.dir, "192.0.2.2 ignored\n", 102);
    try testing.expect(try harness.service.step());
    try testing.expectEqual(@as(u16, 0), store.table().count);
    try harness.stop();
}

// SPEC §1: bind failures and unresolved listener names are startup errors without fallback.
test "native startup rollback on bound and unresolved listeners" {
    var harness: Harness = undefined;
    try harness.init();
    try harness.start();
    defer harness.deinit();
    try testing.expectError(error.BindFailed, harness.address.bind(linux.SOCK.DGRAM));
    try testing.expectError(error.BindFailed, harness.address.bind(linux.SOCK.STREAM));
    const other = try testing.allocator.create(runtime.Runtime);
    defer testing.allocator.destroy(other);
    try testing.expectError(
        error.BindFailed,
        other.init(testing.allocator, testing.io, &harness.settings),
    );
    harness.listen[0] = "unresolved.invalid:53";
    try testing.expectError(
        error.UnresolvedListener,
        other.init(testing.allocator, testing.io, &harness.settings),
    );
    try harness.stop();
}

// SPEC §3.9: local UDP truncation never silently truncates the corresponding TCP answer.
test "native hosts UDP limit TCP full response and malformed datagrams" {
    var temporary = testing.tmpDir(.{});
    defer temporary.cleanup();
    var path_buffer: [128]u8 = undefined;
    const path = try std.fmt.bufPrint(
        &path_buffer,
        ".zig-cache/tmp/{s}/hosts",
        .{temporary.sub_path},
    );
    var source: [4096]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&source);
    for (0..80) |index| try writer.print("192.0.2.{d} large\n", .{index});
    try hostsFile(temporary.dir, writer.buffered(), 100);
    var harness: Harness = undefined;
    try harness.init();
    harness.zones[0].hosts = .{ .path = path, .reload_s = 0 };
    try harness.start();
    defer harness.deinit();
    const datagram = try harness.socket(linux.SOCK.DGRAM);
    defer _ = linux.close(datagram);
    const stream = try harness.socket(linux.SOCK.STREAM);
    defer _ = linux.close(stream);
    var input: [512]u8 = undefined;
    var output: [4096]u8 = undefined;
    const request = try queryName(input[2..], "large.", 1);
    try send(datagram, request);
    const length = try harness.receive(datagram, &output);
    try testing.expect(length <= 512);
    try testing.expect((try wire.Header.decode(output[0..length])).has(.truncated));
    try wire.framePrefix(&input, request.len);
    try send(stream, input[0 .. request.len + 2]);
    const response = try harness.frame(stream, &output);
    try testing.expect(!(try wire.Header.decode(response)).has(.truncated));
    try testing.expectEqual(80, (try wire.Header.decode(response)).counts[1]);
    try send(datagram, &.{1});
    try send(datagram, &(.{0} ** 12));
    const malformed = try harness.receive(datagram, &output);
    try testing.expectEqual(1, (try wire.Header.decode(output[0..malformed])).bits & 15);
    // Deinit itself cancels outstanding accept, receive, timer, and client operations.
}

// SPEC §1: buffer depletion terminates multishot receive and the listener rearms.
test "native provided ring depletion rearms receive" {
    var harness: Harness = undefined;
    try harness.init();
    try harness.start();
    defer harness.deinit();
    const descriptor = try harness.socket(linux.SOCK.DGRAM);
    defer _ = linux.close(descriptor);
    var input: [512]u8 = undefined;
    const request = try query(&input);
    // No SQE has been submitted. Withhold the initial batch before the first receive.
    linux.IoUring.buf_ring_init(harness.service.proctor.provided);
    try send(descriptor, request);
    try testing.expect(try harness.service.step());
    try testing.expectEqual(2, harness.service.proctor.ownership[0].generation);
    linux.IoUring.buf_ring_advance(harness.service.proctor.provided, runtime.proctor.buffers_max);
    var output: [512]u8 = undefined;
    const length = try harness.receive(descriptor, &output);
    try testing.expectEqual(345, (try wire.Header.decode(output[0..length])).id);
    try harness.stop();
}

// SPEC §1: the registered allocation range caps accepted clients and recovers after close.
test "native TCP pool exhaustion and recovery" {
    var harness: Harness = undefined;
    try harness.init();
    try harness.start();
    defer harness.deinit();
    var sockets: [runtime.tcp.clients_max + 1]?linux.fd_t = @splat(null);
    defer for (sockets) |descriptor| {
        if (descriptor) |value| _ = linux.close(value);
    };
    for (sockets[0..runtime.tcp.clients_max], 0..) |*descriptor, index| {
        descriptor.* = try harness.socket(linux.SOCK.STREAM);
        for (0..4) |_| {
            try testing.expect(try harness.service.step());
            if (harness.service.clients[index].state == .connected) break;
        }
        try testing.expectEqual(.connected, harness.service.clients[index].state);
    }
    sockets[runtime.tcp.clients_max] = try harness.socket(linux.SOCK.STREAM);
    for (0..4) |_| {
        try testing.expect(try harness.service.step());
        if (harness.service.proctor.ownership[16].state == .idle) break;
    }
    try testing.expectEqual(.idle, harness.service.proctor.ownership[16].state);
    _ = linux.close(sockets[0].?);
    sockets[0] = null;
    for (0..8) |_| {
        try testing.expect(try harness.service.step());
        if (harness.service.proctor.ownership[16].state == .active) break;
    }
    try testing.expectEqual(.active, harness.service.proctor.ownership[16].state);
    // A new connection must resolve after a slot becomes available.
    const recovered = try harness.socket(linux.SOCK.STREAM);
    defer _ = linux.close(recovered);
    var input: [512]u8 = undefined;
    var output: [512]u8 = undefined;
    const bytes = try query(input[2..]);
    try wire.framePrefix(&input, bytes.len);
    try send(recovered, input[0 .. bytes.len + 2]);
    const response = try harness.frame(recovered, &output);
    try testing.expectEqual(345, (try wire.Header.decode(response)).id);
    try harness.stop();
}
