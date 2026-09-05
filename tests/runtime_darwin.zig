const std = @import("std");
const runtime = @import("runtime");
const testing = std.testing;
const system = std.c;
const wire = runtime.pipeline.wire;
const Response = runtime.Runtime.test_datagram.Response;

const Harness = struct {
    service: *runtime.Runtime,
    settings: runtime.pipeline.resolver.config.Config,
    zones: [1]runtime.pipeline.resolver.config.Zone,
    listen: [1][]const u8,
    text: [64]u8,
    address: runtime.address.Address,

    fn init(self: *Harness) !void {
        try self.initFamily(.ipv4);
    }

    fn initFamily(self: *Harness, family: runtime.udp.Family) !void {
        const text = if (family == .ipv4) "127.0.0.1:1" else "[::1]:1";
        try self.address.parse(text);
        const port = switch (family) {
            .ipv4 => &@as(*system.sockaddr.in, @ptrCast(&self.address.storage)).port,
            .ipv6 => &@as(*system.sockaddr.in6, @ptrCast(&self.address.storage)).port,
        };
        port.* = 0;
        const reservation = try self.address.bind(system.SOCK.STREAM);
        defer _ = system.close(reservation);
        try testing.expectEqual(.SUCCESS, std.posix.errno(system.getsockname(
            reservation,
            @ptrCast(&self.address.storage),
            &self.address.length,
        )));
        self.listen[0] = try std.fmt.bufPrint(&self.text, "{s}:{d}", .{
            if (family == .ipv4) "127.0.0.1" else "[::1]",
            std.mem.bigToNative(u16, port.*),
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

    fn socket(self: *Harness, kind: u32) !system.fd_t {
        const descriptor = system.socket(self.address.storage.family, kind, 0);
        try testing.expect(descriptor >= 0);
        errdefer _ = system.close(descriptor);
        try runtime.address.prepare(descriptor);
        try connectSocket(descriptor, &self.address);
        return descriptor;
    }

    fn receive(self: *Harness, descriptor: system.fd_t, output: []u8) !usize {
        for (0..64) |_| {
            const result = system.recvfrom(descriptor, output.ptr, output.len, 0, null, null);
            switch (std.posix.errno(result)) {
                .SUCCESS => return @intCast(result),
                .AGAIN => try testing.expect(try self.service.step()),
                else => return error.ReceiveFailed,
            }
        }
        return error.TestDeadline;
    }

    fn frame(self: *Harness, descriptor: system.fd_t, output: []u8) ![]const u8 {
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

const Readiness = enum { ready, expired };

fn socketReady(descriptor: system.fd_t, events: i16, timeout_ms: u16) !Readiness {
    var descriptor_poll: system.pollfd = .{ .fd = descriptor, .events = events, .revents = 0 };
    const result = system.poll(@ptrCast(&descriptor_poll), 1, timeout_ms);
    if (result < 0) {
        std.debug.print("socket wait: fd={d} errno={t}\n", .{
            descriptor, std.posix.errno(result),
        });
        return error.SocketWaitFailed;
    }
    if (result == 0) return .expired;
    if (descriptor_poll.revents & system.POLL.NVAL != 0) return error.InvalidSocket;
    // Error readiness must reach SO_ERROR or recv, not masquerade as a deadline.
    if (descriptor_poll.revents & (events | system.POLL.ERR | system.POLL.HUP) == 0)
        return error.UnexpectedReadiness;
    return .ready;
}

fn connectSocket(descriptor: system.fd_t, endpoint: *const runtime.address.Address) !void {
    const result = system.connect(descriptor, @ptrCast(&endpoint.storage), endpoint.length);
    switch (std.posix.errno(result)) {
        .SUCCESS => return,
        .INPROGRESS => {},
        else => return error.ConnectFailed,
    }
    // #1: EINPROGRESS does not permit the first TCP send, even on loopback.
    if (try socketReady(descriptor, system.POLL.OUT, 1000) == .expired)
        return error.ConnectDeadline;
    var failure: c_int = 0;
    var length: system.socklen_t = @sizeOf(c_int);
    try testing.expectEqual(0, system.getsockopt(
        descriptor,
        system.SOL.SOCKET,
        system.SO.ERROR,
        &failure,
        &length,
    ));
    try testing.expectEqual(@as(system.socklen_t, @sizeOf(c_int)), length);
    if (failure != 0) {
        std.debug.print("connect completion: fd={d} SO_ERROR={d}\n", .{ descriptor, failure });
        return error.ConnectFailed;
    }
}

// SPEC §1.2, #1: fixture waits have finite deadlines and reject invalid descriptors.
test "Darwin native client readiness deadline and invalid descriptor" {
    const pair = try socketPair();
    defer _ = system.close(pair[1]);
    defer _ = system.close(pair[0]);
    try testing.expectEqual(.expired, try socketReady(pair[0], system.POLL.IN, 1));
    try send(pair[1], &.{42});
    try testing.expectEqual(.ready, try socketReady(pair[0], system.POLL.IN, 1000));
    const closed = system.dup(pair[0]);
    try testing.expect(closed >= 0);
    try testing.expectEqual(0, system.close(closed));
    try testing.expectError(error.InvalidSocket, socketReady(closed, system.POLL.IN, 1));
}

// SPEC §1.2, #1: writable readiness alone does not establish a TCP connection.
test "Darwin native client rejects refused connection" {
    var endpoint: runtime.address.Address = undefined;
    try endpoint.parse("127.0.0.1:1");
    @as(*system.sockaddr.in, @ptrCast(&endpoint.storage)).port = 0;
    const reservation = system.socket(system.AF.INET, system.SOCK.STREAM, 0);
    try testing.expect(reservation >= 0);
    defer _ = system.close(reservation);
    // A bound socket without listen reserves a port that refuses TCP connections.
    try testing.expectEqual(0, system.bind(
        reservation,
        @ptrCast(&endpoint.storage),
        endpoint.length,
    ));
    try testing.expectEqual(0, system.getsockname(
        reservation,
        @ptrCast(&endpoint.storage),
        &endpoint.length,
    ));
    const descriptor = system.socket(system.AF.INET, system.SOCK.STREAM, 0);
    try testing.expect(descriptor >= 0);
    defer _ = system.close(descriptor);
    try runtime.address.prepare(descriptor);
    try testing.expectError(error.ConnectFailed, connectSocket(descriptor, &endpoint));
}

fn send(descriptor: system.fd_t, bytes: []const u8) !void {
    const result = system.sendto(descriptor, bytes.ptr, bytes.len, 0, null, 0);
    try testing.expectEqual(.SUCCESS, std.posix.errno(result));
    try testing.expectEqual(@as(isize, @intCast(bytes.len)), result);
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

// SPEC §1 and §3.9: real kqueue UDP readiness and ACCEPT serve local loopback queries.
test "Darwin native UDP and TCP repeated queries and cancellation" {
    var harness: Harness = undefined;
    try harness.init();
    try harness.start();
    defer harness.deinit();
    const datagram = try harness.socket(system.SOCK.DGRAM);
    defer _ = system.close(datagram);
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
    const stream = try harness.socket(system.SOCK.STREAM);
    defer _ = system.close(stream);
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
test "Darwin native immediate repeated restart after server TCP close" {
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
    const datagram = try harness.socket(system.SOCK.DGRAM);
    defer _ = system.close(datagram);
    const stream = try harness.socket(system.SOCK.STREAM);
    defer _ = system.close(stream);
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
test "Darwin native immediate repeated restart after partial initialization" {
    var harness: Harness = undefined;
    try harness.init();
    defer testing.allocator.destroy(harness.service);
    var other: Harness = undefined;
    try other.init();
    defer testing.allocator.destroy(other.service);
    const occupied = try other.address.bind(system.SOCK.STREAM);
    defer _ = system.close(occupied);
    const listeners = [_][]const u8{ harness.listen[0], other.listen[0] };
    var settings = harness.settings;
    settings.listen = &listeners;
    for (0..16) |_| {
        try testing.expectError(
            error.BindFailed,
            harness.service.init(testing.allocator, testing.io, &settings),
        );
        // The second UDP socket was opened before its TCP bind failed.
        const released = other.address.bind(system.SOCK.DGRAM) catch null;
        try testing.expect(released != null);
        _ = system.close(released.?);
        try harness.service.init(testing.allocator, testing.io, &harness.settings);
        harness.service.deinit();
    }
}

fn hostsFile(directory: std.Io.Dir, source: []const u8, seconds: i64) !void {
    try directory.writeFile(testing.io, .{ .sub_path = "hosts", .data = source });
    const file = try directory.openFile(testing.io, "hosts", .{});
    defer file.close(testing.io);
    try file.setTimestamps(testing.io, .{
        .modify_timestamp = .{ .new = .fromNanoseconds(@as(i96, seconds) * std.time.ns_per_s) },
    });
}

// SPEC §3.5: real kqueue timers retry failed reloads and zero disables later checks.
test "Darwin native hosts reload timer failure retry and disabled checks" {
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
test "Darwin native startup rollback on bound and unresolved listeners" {
    var harness: Harness = undefined;
    try harness.init();
    try harness.start();
    defer harness.deinit();
    try testing.expectError(error.BindFailed, harness.address.bind(system.SOCK.DGRAM));
    try testing.expectError(error.BindFailed, harness.address.bind(system.SOCK.STREAM));
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
test "Darwin native hosts UDP limit TCP full response and malformed datagrams" {
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
    const datagram = try harness.socket(system.SOCK.DGRAM);
    defer _ = system.close(datagram);
    const stream = try harness.socket(system.SOCK.STREAM);
    defer _ = system.close(stream);
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

// SPEC §1: socket flags forbid a blocking fallback and SIGPIPE process termination.
test "Darwin native nonblocking close-on-exec and no SIGPIPE" {
    var endpoint: runtime.address.Address = undefined;
    try endpoint.parse("127.0.0.1:1");
    const ip: *system.sockaddr.in = @ptrCast(&endpoint.storage);
    ip.port = 0;
    const descriptor = try endpoint.bind(system.SOCK.STREAM);
    defer _ = system.close(descriptor);
    const flags = system.fcntl(descriptor, system.F.GETFL);
    try testing.expect(flags >= 0);
    const nonblocking: c_int = @bitCast(@as(system.O, .{ .NONBLOCK = true }));
    try testing.expect(flags & nonblocking != 0);
    try testing.expect(system.fcntl(descriptor, system.F.GETFD) & system.FD_CLOEXEC != 0);
    var enabled: u32 = 0;
    var length: system.socklen_t = @sizeOf(u32);
    try testing.expectEqual(0, system.getsockopt(
        descriptor,
        system.SOL.SOCKET,
        system.SO.NOSIGPIPE,
        &enabled,
        &length,
    ));
    try testing.expectEqual(1, enabled);
    var input: [1]u8 = undefined;
    try testing.expectEqual(-1, system.recv(descriptor, &input, input.len, 0));
}

// SPEC §1: kqueue setup failure is a startup error, never an alternate backend.
test "Darwin native kqueue setup failure under descriptor quota" {
    var proctor: runtime.proctor.Proctor = undefined;
    var previous: system.rlimit = undefined;
    try testing.expectEqual(0, system.getrlimit(.NOFILE, &previous));
    const limited: system.rlimit = .{ .cur = 0, .max = previous.max };
    try testing.expectEqual(0, system.setrlimit(.NOFILE, &limited));
    defer testing.expectEqual(0, system.setrlimit(.NOFILE, &previous)) catch
        @panic("failed to restore descriptor quota");
    try testing.expectError(error.SetupFailed, proctor.init());
}

// SPEC §1: deletion cancels queued readiness before descriptor and operation-slot reuse.
test "Darwin native one-shot timer deletion generation and registration failure" {
    var proctor: runtime.proctor.Proctor = undefined;
    try proctor.init();
    defer proctor.deinit();
    try testing.expectError(
        error.RegistrationFailed,
        proctor.arm(0, 2147483647, system.EVFILT.READ),
    );
    try testing.expectEqual(.idle, proctor.ownership[0].state);
    try testing.expectEqual(null, proctor.registrations[0]);
    try proctor.arm(0, 0, system.EVFILT.TIMER);
    const generation = proctor.ownership[0].generation;
    try proctor.remove(0);
    try testing.expect(!proctor.pending());
    try proctor.arm(0, 0, system.EVFILT.TIMER);
    try testing.expectEqual(generation + 1, proctor.ownership[0].generation);
    try testing.expectEqual(@as(?u32, 0), try proctor.next());
    try testing.expect(!proctor.pending());
    try proctor.arm(0, 0, system.EVFILT.TIMER);
    try proctor.stop();
    try testing.expect(!proctor.pending());
}

// SPEC §1: response exhaustion drops the request without allocations or lost listener interest.
test "Darwin native UDP response pool exhaustion and recovery" {
    var harness: Harness = undefined;
    try harness.init();
    try harness.start();
    defer harness.deinit();
    const descriptor = try harness.socket(system.SOCK.DGRAM);
    defer _ = system.close(descriptor);
    var input: [512]u8 = undefined;
    var output: [512]u8 = undefined;
    const request = try query(&input);
    // #1: this isolates pool exhaustion, not EAGAIN or write-filter ownership.
    for (&harness.service.responses) |*response| response.listener = 0;
    try send(descriptor, request);
    const generation = harness.service.proctor.ownership[0].generation;
    for (0..4) |_| {
        try testing.expect(try harness.service.step());
        if (harness.service.proctor.ownership[0].generation != generation) break;
    }
    try testing.expect(harness.service.proctor.ownership[0].generation != generation);
    const dropped = system.recvfrom(descriptor, &output, output.len, 0, null, null);
    try testing.expectEqual(.AGAIN, std.posix.errno(dropped));
    for (&harness.service.responses) |*response| response.listener = null;
    for (0..runtime.proctor.buffers_max + 1) |_| {
        try send(descriptor, request);
        _ = try harness.receive(descriptor, &output);
    }
    try harness.stop();
}

// SPEC §1: admission pauses at 128 owned descriptors and resumes after synchronous close.
test "Darwin native TCP pool exhaustion and recovery" {
    var harness: Harness = undefined;
    try harness.init();
    try harness.start();
    defer harness.deinit();
    var sockets: [runtime.tcp.clients_max + 1]?system.fd_t = @splat(null);
    defer for (sockets) |descriptor| {
        if (descriptor) |value| _ = system.close(value);
    };
    for (sockets[0..runtime.tcp.clients_max], 0..) |*descriptor, index| {
        descriptor.* = try harness.socket(system.SOCK.STREAM);
        for (0..4) |_| {
            try testing.expect(try harness.service.step());
            if (harness.service.descriptors[index] != null) break;
        }
        try testing.expect(harness.service.descriptors[index] != null);
    }
    try testing.expectEqual(null, harness.service.proctor.registrations[16]);
    sockets[runtime.tcp.clients_max] = try harness.socket(system.SOCK.STREAM);
    _ = system.close(sockets[0].?);
    sockets[0] = null;
    var input: [512]u8 = undefined;
    var output: [512]u8 = undefined;
    const request = try query(input[2..]);
    try wire.framePrefix(&input, request.len);
    try send(sockets[runtime.tcp.clients_max].?, input[0 .. request.len + 2]);
    const response = try harness.frame(sockets[runtime.tcp.clients_max].?, &output);
    try testing.expectEqual(345, (try wire.Header.decode(response)).id);
    try harness.stop();
}

// SPEC §3.9: IPv6 preserves its source address and supports persistent framed TCP.
test "Darwin native IPv6 UDP TCP and peer half close" {
    var harness: Harness = undefined;
    try harness.initFamily(.ipv6);
    try harness.start();
    defer harness.deinit();
    const datagram = try harness.socket(system.SOCK.DGRAM);
    defer _ = system.close(datagram);
    const stream = try harness.socket(system.SOCK.STREAM);
    defer _ = system.close(stream);
    var input: [512]u8 = undefined;
    var output: [512]u8 = undefined;
    const request = try query(input[2..]);
    try send(datagram, request);
    const length = try harness.receive(datagram, &output);
    try testing.expectEqual(345, (try wire.Header.decode(output[0..length])).id);
    try wire.framePrefix(&input, request.len);
    try send(stream, input[0 .. request.len + 2]);
    try testing.expectEqual(0, system.shutdown(stream, system.SHUT.WR));
    const response = harness.frame(stream, &output) catch &.{};
    try testing.expect(response.len >= 12);
    try testing.expectEqual(345, (try wire.Header.decode(response)).id);
    try testing.expectEqual(0, try harness.receive(stream, &output));
    try harness.stop();
}

// SPEC §3.9: connected clients accept replies only from their original listener endpoint.
test "Darwin native UDP replies retain both listener identities" {
    var first: Harness = undefined;
    try first.init();
    defer testing.allocator.destroy(first.service);
    var other: Harness = undefined;
    try other.init();
    defer testing.allocator.destroy(other.service);
    const listeners = [_][]const u8{ first.listen[0], other.listen[0] };
    first.settings.listen = &listeners;
    try first.service.init(testing.allocator, testing.io, &first.settings);
    defer first.service.deinit();
    const initial = try first.socket(system.SOCK.DGRAM);
    defer _ = system.close(initial);
    const another = try other.socket(system.SOCK.DGRAM);
    defer _ = system.close(another);
    var input: [512]u8 = undefined;
    var output: [512]u8 = undefined;
    const request = try query(&input);
    for ([_]system.fd_t{ initial, another }) |descriptor| {
        try send(descriptor, request);
        const length = try first.receive(descriptor, &output);
        try testing.expectEqual(345, (try wire.Header.decode(output[0..length])).id);
    }
    try first.stop();
}

fn retainedCount(service: *const runtime.Runtime) u32 {
    var count: u32 = 0;
    for (&service.responses) |*response| {
        if (response.listener != null) count += 1;
    }
    return count;
}

fn writeFilters(service: *const runtime.Runtime) !void {
    var counts: [2]u32 = @splat(0);
    for (service.proctor.registrations, 0..) |registration, index| {
        const value = registration orelse continue;
        if (value.filter != system.EVFILT.WRITE) continue;
        try testing.expect(index >= 161);
        try testing.expect(index < 163);
        const listener = index - 161;
        const descriptor: usize = @intCast(service.listeners[listener].udp.?);
        try testing.expectEqual(descriptor, value.ident);
        counts[listener] += 1;
    }
    try testing.expectEqualSlices(u32, &.{ 1, 1 }, &counts);
}

// SPEC §1.2 and §3.9, #1: injected EAGAIN retains actual queries across native write readiness.
test "Darwin native retained EAGAIN bytes destinations and shared filters" {
    var first: Harness = undefined;
    try first.init();
    defer testing.allocator.destroy(first.service);
    var other: Harness = undefined;
    try other.init();
    defer testing.allocator.destroy(other.service);
    try testing.expect(!std.mem.eql(u8, first.listen[0], other.listen[0]));
    const listeners = [_][]const u8{ first.listen[0], other.listen[0] };
    first.settings.listen = &listeners;
    try first.service.init(testing.allocator, testing.io, &first.settings);
    defer first.service.deinit();
    const initial = try first.socket(system.SOCK.DGRAM);
    defer _ = system.close(initial);
    const another = try other.socket(system.SOCK.DGRAM);
    defer _ = system.close(another);
    const sockets = [_]system.fd_t{ initial, another };
    first.service.test_send_errno = .AGAIN;
    var input: [512]u8 = undefined;
    for (0..4) |index| {
        const request = try query(&input);
        std.mem.writeInt(u16, input[0..2], @intCast(700 + index), .big);
        try send(sockets[index % 2], request);
        for (0..64) |_| {
            try testing.expect(try first.service.step());
            if (retainedCount(first.service) == index + 1) break;
        }
        try testing.expectEqual(index + 1, retainedCount(first.service));
    }
    try writeFilters(first.service);
    var saved: [4]Retained = undefined;
    for (&saved, first.service.responses[0..4], 0..) |*snapshot, *response, index| {
        try snapshot.capture(response, sockets[index % 2], @intCast(index));
    }
    try testing.expect(!std.mem.eql(
        u8,
        std.mem.asBytes(&saved[0].address)[0..saved[0].address_length],
        std.mem.asBytes(&saved[1].address)[0..saved[1].address_length],
    ));
    const attempts = first.service.test_send_attempts;
    const generations = [_]u31{
        first.service.proctor.ownership[161].generation,
        first.service.proctor.ownership[162].generation,
    };
    for (0..16) |_| {
        try testing.expect(try first.service.step());
        if (first.service.proctor.ownership[161].generation == generations[0]) continue;
        if (first.service.proctor.ownership[162].generation != generations[1]) break;
    }
    for (generations, 161..) |generation, slot|
        try testing.expect(first.service.proctor.ownership[slot].generation > generation);
    try testing.expect(first.service.test_send_attempts > attempts);
    try testing.expectEqual(4, retainedCount(first.service));
    try writeFilters(first.service);
    for (&saved, first.service.responses[0..4]) |*snapshot, *response|
        try snapshot.expectRetained(response);
    first.service.test_send_errno = null;
    try deliverRetained(&first, &sockets, &saved);
    try first.stop();
}

const Retained = struct {
    bytes: [512]u8,
    length: u32,
    address: system.sockaddr.storage,
    address_length: system.socklen_t,
    listener: u16,

    fn capture(
        self: *Retained,
        response: *const Response,
        socket: system.fd_t,
        index: u16,
    ) !void {
        self.address = std.mem.zeroes(system.sockaddr.storage);
        self.address_length = @sizeOf(system.sockaddr.storage);
        try testing.expectEqual(0, system.getsockname(
            socket,
            @ptrCast(&self.address),
            &self.address_length,
        ));
        self.listener = index % 2;
        self.length = response.length;
        try testing.expect(self.length <= self.bytes.len);
        @memcpy(self.bytes[0..self.length], response.output[0..self.length]);
        const header = try wire.Header.decode(self.bytes[0..self.length]);
        try testing.expectEqual(700 + index, header.id);
        try self.expectRetained(response);
    }

    fn expectRetained(self: *const Retained, response: *const Response) !void {
        try testing.expectEqual(self.listener, response.listener.?);
        try testing.expectEqual(self.length, response.length);
        try testing.expectEqual(self.address_length, response.address_length);
        try testing.expectEqualSlices(
            u8,
            std.mem.asBytes(&self.address)[0..self.address_length],
            std.mem.asBytes(&response.address)[0..response.address_length],
        );
        try testing.expectEqualSlices(
            u8,
            self.bytes[0..self.length],
            response.output[0..response.length],
        );
    }
};

fn deliverRetained(
    harness: *Harness,
    sockets: *const [2]system.fd_t,
    saved: *const [4]Retained,
) !void {
    for (0..16) |_| {
        if (retainedCount(harness.service) == 0) break;
        try testing.expect(try harness.service.step());
    }
    try testing.expectEqual(0, retainedCount(harness.service));
    try testing.expectEqual(null, harness.service.proctor.registrations[161]);
    try testing.expectEqual(null, harness.service.proctor.registrations[162]);
    var output: [512]u8 = undefined;
    for (saved, 0..) |*snapshot, index| {
        // Slot release precedes client readiness. Expiry still proves absent intended delivery.
        const readiness = try socketReady(sockets[index % 2], system.POLL.IN, 1000);
        const received = system.recv(sockets[index % 2], &output, output.len, system.MSG.DONTWAIT);
        const failure = std.posix.errno(received);
        if (received <= 0) std.debug.print(
            "retained delivery: index={d} listener={d} fd={d} readiness={t} recv={d} errno={t}\n",
            .{ index, snapshot.listener, sockets[index % 2], readiness, received, failure },
        );
        try testing.expect(received > 0);
        const length: usize = @intCast(received);
        try testing.expectEqualSlices(u8, snapshot.bytes[0..snapshot.length], output[0..length]);
    }
    for (sockets) |descriptor| {
        const result = system.recv(descriptor, &output, output.len, 0);
        try testing.expectEqual(.AGAIN, std.posix.errno(result));
    }
}

fn socketPair() ![2]system.fd_t {
    var descriptors: [2]system.fd_t = undefined;
    const result = system.socketpair(system.AF.UNIX, system.SOCK.DGRAM, 0, &descriptors);
    try testing.expectEqual(0, result);
    return descriptors;
}

// SPEC §1.2, #1: an already-ready socket must disappear before a distinct sentinel or reuse.
test "Darwin native ready socket deletion sentinel and descriptor reuse" {
    var proctor: runtime.proctor.Proctor = undefined;
    try proctor.init();
    defer proctor.deinit();
    const original = try socketPair();
    defer for (original) |descriptor| {
        _ = system.close(descriptor);
    };
    const replacement = try socketPair();
    defer for (replacement) |descriptor| {
        _ = system.close(descriptor);
    };
    try proctor.arm(0, @intCast(original[0]), system.EVFILT.READ);
    const generation = proctor.ownership[0].generation;
    try send(original[1], &.{42});
    var byte: [1]u8 = undefined;
    const peek = system.recv(original[0], &byte, 1, system.MSG.PEEK | system.MSG.DONTWAIT);
    try testing.expectEqual(1, peek);
    try proctor.remove(0);
    // No EV_ADD, close, or recv can conceal an omitted kernel EV_DELETE here.
    var event: system.Kevent = undefined;
    const immediate: system.timespec = .{ .sec = 0, .nsec = 0 };
    const pending = system.kevent(proctor.descriptor, &.{}, 0, @ptrCast(&event), 1, &immediate);
    try testing.expectEqual(0, pending);
    try proctor.arm(1, 991, system.EVFILT.TIMER);
    try testing.expectEqual(@as(?u32, 1), try proctor.next());
    try testing.expectEqual(original[0], system.dup2(replacement[0], original[0]));
    try proctor.arm(0, @intCast(original[0]), system.EVFILT.READ);
    try testing.expectEqual(generation + 1, proctor.ownership[0].generation);
    try send(replacement[1], &.{99});
    try testing.expectEqual(@as(?u32, 0), try proctor.next());
    try testing.expectEqual(1, system.recv(original[0], &byte, 1, system.MSG.DONTWAIT));
    try testing.expectEqual(99, byte[0]);
    try testing.expect(!proctor.pending());
}

// SPEC §1.2, #1: actual kevent delivery rejects stale descriptor identities and generations.
test "Darwin native stale event identity and generation rejection" {
    var proctor: runtime.proctor.Proctor = undefined;
    try proctor.init();
    defer proctor.deinit();
    const pair = try socketPair();
    defer for (pair) |descriptor| {
        _ = system.close(descriptor);
    };
    try proctor.arm(0, @intCast(pair[0]), system.EVFILT.READ);
    try send(pair[1], &.{1});
    const identity = proctor.registrations[0].?.ident;
    proctor.registrations[0].?.ident = @intCast(pair[1]);
    try testing.expectError(error.InvalidCompletion, proctor.next());
    proctor.registrations[0].?.ident = identity;
    // The rejected one-shot event already left the kernel. Recreate only its old token.
    const stale: system.Kevent = .{
        .ident = identity,
        .filter = system.EVFILT.READ,
        .flags = system.EV.ADD | system.EV.ONESHOT,
        .fflags = 0,
        .data = 0,
        .udata = proctor.ownership[0].token(0),
    };
    proctor.ownership[0].generation += 1;
    const result = system.kevent(proctor.descriptor, @ptrCast(&stale), 1, &.{}, 0, null);
    try testing.expectEqual(0, result);
    try testing.expectError(error.InvalidCompletion, proctor.next());
}

// SPEC §3.9, #1: Darwin sockaddr metadata must match both external and embedded lengths.
test "Darwin native malformed datagram metadata" {
    var source: system.sockaddr.storage = std.mem.zeroes(system.sockaddr.storage);
    source.family = system.AF.INET;
    source.len = @sizeOf(system.sockaddr.in);
    const datagram = runtime.Runtime.test_datagram;
    try testing.expectEqual(.ipv4, try datagram.family(&source, source.len));
    try testing.expectError(error.InvalidDatagram, datagram.family(&source, source.len - 1));
    source.len -= 1;
    try testing.expectError(
        error.InvalidDatagram,
        datagram.family(&source, @sizeOf(system.sockaddr.in)),
    );
    source.family = system.AF.UNIX;
    try testing.expectError(error.InvalidDatagram, datagram.family(&source, source.len));
}

// SPEC §1.2, #1: kernel accept quota failure pauses admission until the real timer fires.
test "Darwin native accept quota timer recovery" {
    var harness: Harness = undefined;
    try harness.init();
    try harness.start();
    defer harness.deinit();
    const stream = try harness.socket(system.SOCK.STREAM);
    defer _ = system.close(stream);
    var previous: system.rlimit = undefined;
    try testing.expectEqual(0, system.getrlimit(.NOFILE, &previous));
    const limited: system.rlimit = .{ .cur = 0, .max = previous.max };
    try testing.expectEqual(0, system.setrlimit(.NOFILE, &limited));
    defer testing.expectEqual(0, system.setrlimit(.NOFILE, &previous)) catch
        @panic("failed to restore descriptor quota");
    for (0..4) |_| {
        try testing.expect(try harness.service.step());
        if (harness.service.proctor.registrations[16] == null) break;
    }
    try testing.expectEqual(null, harness.service.proctor.registrations[16]);
    try testing.expectEqual(null, harness.service.descriptors[0]);
    const generation = harness.service.proctor.ownership[16].generation;
    const timer_generation = harness.service.proctor.ownership[32].generation;
    try testing.expectEqual(0, system.setrlimit(.NOFILE, &previous));
    try testing.expect(try harness.service.step());
    try testing.expectEqual(timer_generation + 1, harness.service.proctor.ownership[32].generation);
    try testing.expectEqual(generation + 1, harness.service.proctor.ownership[16].generation);
    try testing.expect(harness.service.proctor.registrations[16] != null);
    // Rearm does not order accept ahead of the next timer or an interrupted kevent.
    for (0..4) |_| {
        try testing.expect(try harness.service.step());
        if (harness.service.descriptors[0] != null) break;
    }
    if (harness.service.descriptors[0] == null) std.debug.print(
        "quota recovery: accept_generation={d} timer_generation={d} armed={}\n",
        .{
            harness.service.proctor.ownership[16].generation,
            harness.service.proctor.ownership[32].generation,
            harness.service.proctor.registrations[16] != null,
        },
    );
    try testing.expect(harness.service.descriptors[0] != null);
    const accepted = harness.service.descriptors[0].?;
    const nonblocking: c_int = @bitCast(@as(system.O, .{ .NONBLOCK = true }));
    try testing.expect(system.fcntl(accepted, system.F.GETFL) & nonblocking != 0);
    try testing.expect(system.fcntl(accepted, system.F.GETFD) & system.FD_CLOEXEC != 0);
    var input: [512]u8 = undefined;
    var output: [512]u8 = undefined;
    const request = try query(input[2..]);
    try wire.framePrefix(&input, request.len);
    try send(stream, input[0 .. request.len + 2]);
    try testing.expectEqual(345, (try wire.Header.decode(try harness.frame(stream, &output))).id);
    try harness.stop();
}
