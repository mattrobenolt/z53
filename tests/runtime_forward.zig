const std = @import("std");
const builtin = @import("builtin");
const runtime = @import("runtime");
const testing = std.testing;
const logging = @import("runtime_log.zig");
const system = std.c;
const wire = runtime.pipeline.wire;
const config = runtime.pipeline.resolver.config;

const Harness = struct {
    service: *runtime.Runtime,
    allocator: testing.FailingAllocator,
    settings: config.Config,
    zones: [2]config.Zone,
    upstreams: [2]config.Upstream,
    listen: [1][]const u8,
    text: [64]u8,
    upstream_text: [64]u8,
    address: runtime.address.Address,
    upstream_address: runtime.address.Address,
    listener: ?system.fd_t,
    state: enum { prepared, running, released },
    peer: ?system.fd_t = null,

    fn init(self: *Harness) !void {
        self.peer = null;
        self.listener = null;
        self.state = .prepared;
        self.allocator = testing.FailingAllocator.init(testing.allocator, .{});
        self.service = try self.allocator.allocator().create(runtime.Runtime);
        errdefer self.allocator.allocator().destroy(self.service);
        const reservation = try endpoint(&self.address, &self.text);
        defer _ = system.close(reservation);
        self.listener = try endpoint(&self.upstream_address, &self.upstream_text);
        self.listen = .{std.mem.sliceTo(&self.text, 0)};
        self.upstreams = .{
            .{ .address = std.mem.sliceTo(&self.upstream_text, 0), .force_tcp = true },
            .{ .address = std.mem.sliceTo(&self.upstream_text, 0), .force_tcp = true },
        };
        self.zones = .{
            .{ .suffix = ".", .upstreams = self.upstreams[0..1], .cache = null },
            .{ .suffix = "example.", .upstreams = self.upstreams[1..2], .cache = null },
        };
        self.settings = .{ .listen = &self.listen, .zones = self.zones[0..1] };
    }

    fn start(self: *Harness) !void {
        std.debug.assert(self.state == .prepared);
        try self.service.init(self.allocator.allocator(), testing.io, &self.settings);
        self.state = .running;
    }

    fn deinit(self: *Harness) void {
        if (self.state != .released) self.release();
        self.* = undefined;
    }

    fn release(self: *Harness) void {
        std.debug.assert(self.state != .released);
        if (self.state == .running) self.service.deinit();
        self.allocator.allocator().destroy(self.service);
        if (self.peer) |descriptor| _ = system.close(descriptor);
        if (self.listener) |descriptor| _ = system.close(descriptor);
        self.state = .released;
    }

    fn client(self: *Harness, kind: u32) !system.fd_t {
        const descriptor = system.socket(self.address.storage.family, kind, 0);
        if (descriptor < 0) return error.SocketFailed;
        errdefer _ = system.close(descriptor);
        // Test clients can block during their local connect. Runtime sockets cannot.
        if (system.connect(descriptor, @ptrCast(&self.address.storage), self.address.length) < 0)
            return error.ConnectFailed;
        try nonblocking(descriptor);
        return descriptor;
    }

    fn phase(self: *Harness, wanted: @FieldType(runtime.forward.Session, "state")) !u16 {
        for (0..256) |_| {
            for (&self.service.forward.sessions, 0..) |*session, index| {
                if (session.state == wanted) return @intCast(index);
            }
            try testing.expect(try self.service.step());
        }
        return error.PhaseNotReached;
    }

    fn request(self: *Harness, output: []u8) !struct { bytes: []const u8, session: u16 } {
        if (self.peer == null) {
            _ = try self.phase(.writing);
            const descriptor = system.accept(self.listener.?, null, null);
            if (descriptor < 0) return error.AcceptFailed;
            self.peer = descriptor;
            try nonblocking(descriptor);
        }
        const index = try self.phase(.read_prefix);
        var reader: PeerReader = .{ .descriptor = self.peer.? };
        return .{ .bytes = try peerFrame(&reader, output), .session = index };
    }

    fn phaseOther(
        self: *Harness,
        wanted: @FieldType(runtime.forward.Session, "state"),
        excluded: u16,
    ) !u16 {
        for (0..256) |_| {
            for (&self.service.forward.sessions, 0..) |*session, index| {
                if (index == excluded) continue;
                if (session.state == wanted) return @intCast(index);
            }
            try testing.expect(try self.service.step());
        }
        return error.PhaseNotReached;
    }

    fn rejected(self: *Harness, index: u16) !void {
        // Body state proves the preceding prefix completed before the next-prefix assertion.
        _ = try self.phase(.read_body);
        for (0..128) |_| {
            const session = &self.service.forward.sessions[index];
            if (session.state == .idle) try testing.expectEqual(.read_prefix, session.state);
            if (session.state == .read_prefix) {
                if (session.offset == 0) return;
            }
            try testing.expect(try self.service.step());
        }
        return error.FrameNotRejected;
    }

    fn sendClient(self: *Harness, descriptor: system.fd_t, bytes: []const u8) !void {
        var offset: usize = 0;
        for (0..512) |_| {
            if (offset == bytes.len) return;
            const count = system.send(descriptor, bytes[offset..].ptr, bytes.len - offset, 0);
            if (count > 0) {
                offset += @intCast(count);
            } else {
                if (std.posix.errno(count) != .AGAIN) return error.SendFailed;
                try testing.expect(try self.service.step());
            }
        }
        return error.SendIncomplete;
    }

    fn receive(self: *Harness, descriptor: system.fd_t, output: []u8) !usize {
        for (0..512) |_| {
            const count = system.recv(descriptor, output.ptr, output.len, 0);
            if (count >= 0) return @intCast(count);
            if (std.posix.errno(count) != .AGAIN) return error.ReceiveFailed;
            try testing.expect(try self.service.step());
        }
        return error.ResponseNotReceived;
    }

    fn frame(self: *Harness, descriptor: system.fd_t, output: []u8) ![]const u8 {
        var length: usize = 0;
        var wanted: usize = 2;
        for (0..128) |_| {
            const count = try self.receive(descriptor, output[length..wanted]);
            if (count == 0) return error.Closed;
            length += count;
            if (length != wanted) continue;
            if (wanted != 2) return output[2..wanted];
            wanted = 2 + @as(usize, wire.integer(u16, output[0..2]));
            if (wanted > output.len) return error.ShortBuffer;
        }
        return error.ShortFrame;
    }

    fn stop(self: *Harness) !void {
        try self.service.stop();
        for (0..runtime.proctor.operations_max * 3) |_| {
            if (!try self.service.step()) return;
        }
        return error.CancellationDidNotDrain;
    }
};

// The owned upstream peer never consumes bytes from the next queued frame.
fn peerFrame(reader: anytype, output: []u8) ![]const u8 {
    if (output.len < 2) return error.ShortBuffer;
    const deadline_ns = try runtime.nowNs() + 2 * std.time.ns_per_s;
    var offset: usize = 0;
    var wanted: usize = 2;
    for (0..wire.message_bytes_max + 2) |_| {
        const count = try reader.read(output[offset..wanted], deadline_ns);
        if (count == 0) return error.Closed;
        if (count > wanted - offset) return error.ShortFrame;
        offset += count;
        if (offset != wanted) continue;
        if (wanted != 2) return output[2..wanted];
        const length: usize = wire.integer(u16, output[0..2]);
        if (length < 12) return error.ShortFrame;
        wanted = 2 + length;
        if (wanted > output.len) return error.ShortBuffer;
    }
    return error.ShortFrame;
}

const PeerReader = struct {
    descriptor: system.fd_t,

    fn read(self: *PeerReader, output: []u8, deadline_ns: u64) !usize {
        std.debug.assert(output.len > 0);
        for (0..128) |_| {
            const now_ns = try runtime.nowNs();
            if (now_ns >= deadline_ns) return error.PeerReadDeadline;
            const count = system.recv(self.descriptor, output.ptr, output.len, 0);
            if (count >= 0) return @intCast(count);
            switch (std.posix.errno(count)) {
                .INTR => continue,
                .AGAIN => {},
                else => return error.ReceiveFailed,
            }
            var descriptor: system.pollfd = .{
                .fd = self.descriptor,
                .events = system.POLL.IN,
                .revents = 0,
            };
            const remaining_ns = deadline_ns -| try runtime.nowNs();
            const timeout_ms: c_int = @intCast(std.math.divCeil(
                u64,
                remaining_ns,
                std.time.ns_per_ms,
            ) catch unreachable);
            const ready = system.poll(@ptrCast(&descriptor), 1, timeout_ms);
            if (ready < 0) {
                if (std.posix.errno(ready) != .INTR) return error.ReceiveFailed;
            }
        }
        return error.PeerReadDeadline;
    }
};

fn endpoint(address: *runtime.address.Address, output: *[64]u8) !system.fd_t {
    try address.parse("127.0.0.1:1");
    const ip: *system.sockaddr.in = @ptrCast(&address.storage);
    ip.port = 0;
    const descriptor = try address.bind(system.SOCK.STREAM);
    errdefer _ = system.close(descriptor);
    if (system.getsockname(descriptor, @ptrCast(&address.storage), &address.length) < 0)
        return error.AddressFailed;
    @memset(output, 0);
    _ = try std.fmt.bufPrint(output, "127.0.0.1:{d}", .{std.mem.bigToNative(u16, ip.port)});
    return descriptor;
}

fn nonblocking(descriptor: system.fd_t) !void {
    const flags = system.fcntl(descriptor, system.F.GETFL);
    const value: c_int = @bitCast(@as(system.O, .{ .NONBLOCK = true }));
    if (system.fcntl(descriptor, system.F.SETFL, flags | value) < 0) return error.SocketFailed;
}

fn send(descriptor: system.fd_t, bytes: []const u8) !void {
    const count = system.send(descriptor, bytes.ptr, bytes.len, 0);
    try testing.expectEqual(@as(isize, @intCast(bytes.len)), count);
}

fn query(output: []u8, id: u16, text: []const u8) ![]const u8 {
    var encoder: wire.Encoder = undefined;
    var name: wire.Name = undefined;
    try name.fromText(text);
    try encoder.init(output, &.{ .id = id, .bits = 0x100 });
    try encoder.question(&name, 1, 1);
    return encoder.finish();
}

fn answer(output: []u8, request: []const u8, rcode: u4, count: u16) ![]const u8 {
    const packet = try testing.allocator.create(wire.Packet);
    defer testing.allocator.destroy(packet);
    try packet.parse(request);
    var parsed: runtime.pipeline.resolver.Request = undefined;
    try parsed.init(packet);
    var encoder: wire.Encoder = undefined;
    try encoder.init(output[2..], &.{ .id = packet.header.id, .bits = 0x8500 | @as(u16, rcode) });
    try encoder.question(&parsed.name, parsed.kind, parsed.class);
    for (0..count) |index| {
        const record: wire.Record = .{
            .owner = 0,
            .kind = 1,
            .class = 1,
            .ttl_s = 1,
            .data_start = 0,
            .data_end = 0,
            .section = .answer,
        };
        const offset = try encoder.beginRecord(&parsed.name, &record);
        try encoder.bytes(&.{ 192, 0, 2, @intCast(index % 256) });
        encoder.endRecord(offset);
    }
    const bytes = try encoder.finish();
    try wire.framePrefix(output, bytes.len);
    return output[0 .. bytes.len + 2];
}

// SPEC §§3.2, 3.6, 3.9, 4: native client envelopes and logs retain stream reuse.
test "forward native both clients reuse queued frames and allocation guard logging" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    try harness.start();
    var logs: logging.Capture = .{};
    harness.service.forward.logger = logs.sink();
    const allocations = harness.allocator.alloc_index;
    harness.allocator.fail_index = allocations;
    const datagram = try harness.client(system.SOCK.DGRAM);
    defer _ = system.close(datagram);
    const stream = try harness.client(system.SOCK.STREAM);
    defer _ = system.close(stream);
    var input: [512]u8 = undefined;
    var upstream: [65537]u8 = undefined;
    var response: [65537]u8 = undefined;
    var output: [65537]u8 = undefined;
    const bytes = try query(input[2..], 42, "forward.example.");
    try send(datagram, bytes);
    const first = try harness.request(&upstream);
    try linkedDeadline(&harness, first.session);
    const generation = harness.service.forward.sessions[first.session].generation;
    try testing.expectEqual(
        harness.service.forward.sessions[first.session].identifier,
        (try wire.Header.decode(first.bytes)).id,
    );
    try send(harness.peer.?, try answer(&response, first.bytes, 0, 2));
    const length = try harness.receive(datagram, &output);
    try testing.expectEqual(42, (try wire.Header.decode(output[0..length])).id);
    try testing.expectEqual(0x8580, (try wire.Header.decode(output[0..length])).bits);
    try wire.framePrefix(&input, bytes.len);
    try send(stream, input[0 .. bytes.len + 2]);
    try send(stream, input[0 .. bytes.len + 2]);
    try testing.expectEqual(0, system.shutdown(stream, system.SHUT.WR));
    for (0..2) |_| {
        const request = try harness.request(&upstream);
        try testing.expectEqual(first.session, request.session);
        try testing.expectEqual(
            generation,
            harness.service.forward.sessions[request.session].generation,
        );
        try send(harness.peer.?, try answer(&response, request.bytes, 0, 2));
        const received = try harness.frame(stream, &output);
        try testing.expectEqual(42, (try wire.Header.decode(received)).id);
        try testing.expectEqual(2, (try wire.Header.decode(received)).counts[1]);
    }
    try testing.expectEqual(allocations, harness.allocator.alloc_index);
    try testing.expect(!harness.allocator.has_induced_failure);
    try testing.expectEqual(3, logs.count("event=query"));
    try testing.expectEqual(1, logs.count("proto=udp client="));
    try testing.expectEqual(2, logs.count("proto=tcp client="));
    try testing.expectEqual(3, logs.count("upstream_proto=tcp"));
    try logs.client(datagram, .udp);
    try logs.client(stream, .tcp);
    try harness.stop();
}

// SPEC §§3.6, 3.7: admitted SERVFAIL stops the sequence and cache hits do not contact a peer.
test "forward native SERVFAIL stops failover and caches five seconds" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    harness.zones[0].upstreams = &harness.upstreams;
    harness.zones[0].cache = .{ .capacity = 1 };
    try harness.start();
    const client = try harness.client(system.SOCK.DGRAM);
    defer _ = system.close(client);
    var input: [512]u8 = undefined;
    var upstream: [512]u8 = undefined;
    var response: [512]u8 = undefined;
    var output: [512]u8 = undefined;
    const bytes = try query(&input, 73, "failure.example.");
    try send(client, bytes);
    const request = try harness.request(&upstream);
    try send(harness.peer.?, try answer(&response, request.bytes, 2, 0));
    _ = try harness.receive(client, &output);
    try testing.expectEqual(2, (try wire.Header.decode(&output)).bits & 15);
    try testing.expectEqual(
        5,
        harness.service.pipeline.zones[0].cache.denial.entries[0].lifetime_s,
    );
    const generation = harness.service.forward.sessions[request.session].generation;
    const allocations = harness.allocator.alloc_index;
    harness.allocator.fail_index = allocations;
    try send(client, bytes);
    _ = try harness.receive(client, &output);
    try testing.expectEqual(
        generation,
        harness.service.forward.sessions[request.session].generation,
    );
    const count = system.recv(harness.peer.?, &upstream, upstream.len, 0);
    try testing.expectEqual(system.E.AGAIN, std.posix.errno(count));
    try testing.expectEqual(allocations, harness.allocator.alloc_index);
    try testing.expect(!harness.allocator.has_induced_failure);
    try harness.stop();
}

// SPEC §3.9: final client limits truncate UDP RRsets, but TCP receives the full forwarded answer.
test "forward native large UDP truncation and full TCP" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    try harness.start();
    var input: [512]u8 = undefined;
    var upstream: [65537]u8 = undefined;
    var response: [65537]u8 = undefined;
    var output: [65537]u8 = undefined;
    const bytes = try query(input[2..], 91, "large.example.");
    for ([_]u32{ system.SOCK.DGRAM, system.SOCK.STREAM }) |kind| {
        const client = try harness.client(kind);
        defer _ = system.close(client);
        try wire.framePrefix(&input, bytes.len);
        try send(client, if (kind == system.SOCK.DGRAM) bytes else input[0 .. bytes.len + 2]);
        const request = try harness.request(&upstream);
        try send(harness.peer.?, try answer(&response, request.bytes, 0, 80));
        if (kind == system.SOCK.DGRAM) {
            const length = try harness.receive(client, &output);
            try testing.expect(length <= 512);
            try testing.expect((try wire.Header.decode(output[0..length])).has(.truncated));
        } else {
            const result = try harness.frame(client, &output);
            try testing.expectEqual(80, (try wire.Header.decode(result)).counts[1]);
            try testing.expect(!(try wire.Header.decode(result)).has(.truncated));
        }
    }
    try harness.stop();
}

// SPEC §§1, 3.6: session and endpoint metadata fit the reviewed budgets on each target.
test "forward storage and nanosecond duration bounds" {
    try testing.expect(@sizeOf(runtime.forward.Forward) <= runtime.forward.storage_bytes_max);
    try testing.expectEqual(32, runtime.forward.transactions_max);
    try testing.expectEqual(32, runtime.forward.sessions_max);
    try testing.expectEqual(1024, runtime.forward.endpoints_max);
    try testing.expectEqual(1000000, runtime.forward.duration(0.001));
    try testing.expectEqual(1500000, runtime.forward.duration(0.0015));
    std.debug.print("forward storage={d} runtime={d} ip={d} target={s}\n", .{
        @sizeOf(runtime.forward.Forward), @sizeOf(runtime.Runtime),
        @sizeOf(std.Io.net.IpAddress),    @tagName(builtin.os.tag),
    });
    std.debug.print("forward backend={d} transaction={d} session={d}\n", .{
        @sizeOf(@FieldType(runtime.Runtime, "upstreams")),
        @sizeOf(runtime.forward.Transaction),
        @sizeOf(runtime.forward.Session),
    });
}

fn ednsQuery(output: []u8, id: u16, text: []const u8, cookie: u8) ![]const u8 {
    var encoder: wire.Encoder = undefined;
    var name: wire.Name = undefined;
    try name.fromText(text);
    try encoder.init(output, &.{ .id = id, .bits = 0x110 });
    try encoder.question(&name, 1, 1);
    const options = [_]u8{ 0, 10, 0, 8, cookie, 2, 3, 4, 5, 6, 7, 8, 253, 232, 0, 3, 9, 8, 7 };
    try wire.rewrite.writeOpt(&encoder, &.{
        .payload_bytes = 1400,
        .flags = 0x8000,
        .options = &options,
    });
    return encoder.finish();
}

// SPEC §§3.6, 3.9: concurrent transactions own names, IDs, options, and UDP destinations.
test "forward native concurrent identity EDNS COOKIE DO and unknown options" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    try harness.start();
    const first = try harness.client(system.SOCK.DGRAM);
    defer _ = system.close(first);
    const second = try harness.client(system.SOCK.DGRAM);
    defer _ = system.close(second);
    var input: [512]u8 = undefined;
    var request_one: [512]u8 = undefined;
    var request_two: [512]u8 = undefined;
    var response: [512]u8 = undefined;
    var output: [512]u8 = undefined;
    const packet = try testing.allocator.create(wire.Packet);
    defer testing.allocator.destroy(packet);
    try send(first, try ednsQuery(&input, 53, "first.example.", 11));
    const one = try harness.request(&request_one);
    try send(second, try ednsQuery(&input, 53, "second.example.", 22));
    _ = try harness.phaseOther(.writing, one.session);
    const peer_two = system.accept(harness.listener.?, null, null);
    if (peer_two < 0) return error.AcceptFailed;
    defer _ = system.close(peer_two);
    const two = try harness.phaseOther(.read_prefix, one.session);
    try testing.expect(one.session != two);
    try nonblocking(peer_two);
    var reader: PeerReader = .{ .descriptor = peer_two };
    const two_frame = try peerFrame(&reader, &request_two);
    for ([_][]const u8{ one.bytes, two_frame }) |bytes| {
        try packet.parse(bytes);
        const opt = packet.records[packet.opt.?];
        try testing.expectEqual(1232, opt.class);
        try testing.expectEqual(0x8000, opt.ttl_s);
        try testing.expectEqual(19, opt.data_end - opt.data_start);
        try testing.expectEqualSlices(
            u8,
            &.{ 253, 232, 0, 3, 9, 8, 7 },
            bytes[opt.data_start + 12 .. opt.data_end],
        );
    }
    try send(peer_two, try answer(&response, two_frame, 0, 1));
    const received_two = try harness.receive(second, &output);
    try packet.parse(output[0..received_two]);
    try checkCookie(packet, 22, "second.example.");
    try send(harness.peer.?, try answer(&response, one.bytes, 0, 1));
    const received_one = try harness.receive(first, &output);
    try packet.parse(output[0..received_one]);
    try checkCookie(packet, 11, "first.example.");
    try harness.stop();
}

fn checkCookie(packet: *wire.Packet, cookie: u8, text: []const u8) !void {
    try testing.expectEqual(53, packet.header.id);
    const opt = packet.records[packet.opt.?];
    try testing.expectEqual(1400, opt.class);
    try testing.expectEqual(0x8000, opt.ttl_s);
    try testing.expectEqual(12, opt.data_end - opt.data_start);
    try testing.expectEqual(cookie, packet.bytes[opt.data_start + 4]);
    var cursor: usize = 12;
    const question_value = try packet.readQuestion(&cursor);
    var expected: wire.Name = undefined;
    var actual: wire.Name = undefined;
    try expected.fromText(text);
    try packet.name(&actual, question_value.name);
    try testing.expect(actual.equal(&expected));
}

// SPEC §3.6: rejected responses neither publish nor renew the absolute response deadline.
test "forward native ID question QR opcode malformed admission and partial framing" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    harness.zones[0].cache = .{ .capacity = 1 };
    try harness.start();
    const client = try harness.client(system.SOCK.DGRAM);
    defer _ = system.close(client);
    var input: [512]u8 = undefined;
    var upstream: [512]u8 = undefined;
    var response: [512]u8 = undefined;
    var output: [512]u8 = undefined;
    try send(client, try query(&input, 18, "admit.example."));
    const request = try harness.request(&upstream);
    const session = &harness.service.forward.sessions[request.session];
    const deadline_ns = session.deadline_ns;
    for (0..8) |mutation| {
        const bytes = try answer(&response, request.bytes, 0, 1);
        switch (mutation) {
            0 => response[2] ^= 1,
            1 => response[15] = 'z',
            2 => response[4] &= 0x7f,
            3 => response[4] |= 0x08,
            4 => response[9] = 2,
            5 => response[7] = 2,
            6 => response[32] ^= 1,
            7 => response[30] ^= 1,
            else => unreachable,
        }
        try send(harness.peer.?, bytes);
        try harness.rejected(request.session);
        try testing.expectEqual(deadline_ns, session.deadline_ns);
        try emptyCache(&harness);
    }
    try send(harness.peer.?, try extraQuestion(&response, request.bytes));
    try harness.rejected(request.session);
    try emptyCache(&harness);
    const bytes = try answer(&response, request.bytes, 0, 1);
    // Case differences are not question mismatches.
    response[15] = 'A';
    try send(harness.peer.?, bytes[0..1]);
    for (0..8) |_| {
        try testing.expect(try harness.service.step());
        if (session.offset == 1) break;
    }
    try testing.expectEqual(1, session.offset);
    try testing.expectEqual(deadline_ns, session.deadline_ns);
    try send(harness.peer.?, bytes[1..8]);
    _ = try harness.phase(.read_body);
    for (0..8) |_| {
        try testing.expect(try harness.service.step());
        if (session.offset == 8) break;
    }
    try testing.expectEqual(8, session.offset);
    try testing.expectEqual(deadline_ns, session.deadline_ns);
    try send(harness.peer.?, bytes[8..]);
    const length = try harness.receive(client, &output);
    try testing.expectEqual(18, (try wire.Header.decode(output[0..length])).id);
    try testing.expectEqual(1, (try wire.Header.decode(output[0..length])).counts[1]);
    try harness.stop();
}

// SPEC §§3.6, 3.7: a real silent connected peer exhausts a configured one-millisecond exchange.
test "forward native precise silent deadline and terminal cache" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    harness.zones[0].read_timeout_s = 0.001;
    harness.zones[0].cache = .{ .capacity = 1 };
    try harness.start();
    const client = try harness.client(system.SOCK.DGRAM);
    defer _ = system.close(client);
    var input: [512]u8 = undefined;
    var output: [512]u8 = undefined;
    try send(client, try query(&input, 19, "silent.example."));
    const length = try harness.receive(client, &output);
    try testing.expectEqual(2, (try wire.Header.decode(output[0..length])).bits & 15);
    const entry = &harness.service.pipeline.zones[0].cache.denial.entries[0];
    try testing.expectEqual(5, entry.lifetime_s);
    try testing.expect(entry.bytes != null);
    try testing.expectEqual(1, harness.service.forward.transactions[0].cursor);
    try harness.stop();
}

// SPEC §5.1: an unsupported first member cannot be skipped or treated as transport exhaustion.
test "forward native unsupported first upstream stays uncached" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    harness.upstreams[0].address = "dns.example:853";
    harness.zones[0].upstreams = &harness.upstreams;
    harness.zones[0].cache = .{ .capacity = 1 };
    harness.zones[0].serve_stale_s = 300;
    try harness.start();
    const client = try harness.client(system.SOCK.DGRAM);
    defer _ = system.close(client);
    var input: [512]u8 = undefined;
    var output: [512]u8 = undefined;
    try send(client, try query(&input, 20, "unsupported.example."));
    const length = try harness.receive(client, &output);
    try testing.expectEqual(2, (try wire.Header.decode(output[0..length])).bits & 15);
    for (&harness.service.forward.sessions) |*session|
        try testing.expectEqual(.vacant, session.state);
    try testing.expectEqual(null, harness.service.pipeline.zones[0].cache.denial.entries[0].bytes);
    try harness.stop();
}

// SPEC §3.6: a reset advances the exact configured sequence once, without parallel attempts.
test "forward native reset sequential failure-only failover" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    harness.zones[0].upstreams = &harness.upstreams;
    try harness.start();
    const client = try harness.client(system.SOCK.DGRAM);
    defer _ = system.close(client);
    var input: [512]u8 = undefined;
    var upstream: [512]u8 = undefined;
    var response: [512]u8 = undefined;
    var output: [512]u8 = undefined;
    try send(client, try query(&input, 21, "reset.example."));
    const first = try harness.request(&upstream);
    try testing.expectEqual(0, harness.service.forward.sessions[first.session].endpoint);
    const linger: system.linger = .{ .onoff = 1, .linger = 0 };
    try testing.expectEqual(0, system.setsockopt(
        harness.peer.?,
        system.SOL.SOCKET,
        system.SO.LINGER,
        &linger,
        @sizeOf(system.linger),
    ));
    _ = system.close(harness.peer.?);
    harness.peer = null;
    const second = try harness.request(&upstream);
    try testing.expectEqual(1, harness.service.forward.sessions[second.session].endpoint);
    const transaction = harness.service.forward.sessions[second.session].transaction.?;
    try testing.expectEqual(2, harness.service.forward.transactions[transaction].cursor);
    try send(harness.peer.?, try answer(&response, second.bytes, 0, 1));
    const length = try harness.receive(client, &output);
    try testing.expectEqual(21, (try wire.Header.decode(output[0..length])).id);
    try testing.expectEqual(1, (try wire.Header.decode(output[0..length])).counts[1]);
    try harness.stop();
}

// SPEC §3.6: an owned non-listening endpoint fails before the second configured endpoint answers.
test "forward native refusal or deadline advances configured endpoint" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var unavailable: runtime.address.Address = undefined;
    try unavailable.parse("127.0.0.1:1");
    const ip: *system.sockaddr.in = @ptrCast(&unavailable.storage);
    ip.port = 0;
    const reserved = system.socket(system.AF.INET, system.SOCK.STREAM, 0);
    try testing.expect(reserved >= 0);
    defer _ = system.close(reserved);
    try testing.expectEqual(
        0,
        system.bind(reserved, @ptrCast(&unavailable.storage), unavailable.length),
    );
    try testing.expectEqual(
        0,
        system.getsockname(reserved, @ptrCast(&unavailable.storage), &unavailable.length),
    );
    var text: [64]u8 = undefined;
    harness.upstreams[0].address = try std.fmt.bufPrint(&text, "127.0.0.1:{d}", .{
        std.mem.bigToNative(u16, ip.port),
    });
    harness.zones[0].upstreams = &harness.upstreams;
    harness.zones[0].read_timeout_s = 0.05;
    try harness.start();
    const client = try harness.client(system.SOCK.DGRAM);
    defer _ = system.close(client);
    var input: [512]u8 = undefined;
    var upstream: [512]u8 = undefined;
    var response: [512]u8 = undefined;
    var output: [512]u8 = undefined;
    try send(client, try query(&input, 22, "sequence.example."));
    const request = try harness.request(&upstream);
    try testing.expectEqual(1, harness.service.forward.sessions[request.session].endpoint);
    try send(harness.peer.?, try answer(&response, request.bytes, 0, 1));
    const length = try harness.receive(client, &output);
    try testing.expectEqual(1, (try wire.Header.decode(output[0..length])).counts[1]);
    try harness.stop();
}

// SPEC §3.7: stale data follows real supported exhaustion, never an admitted DNS SERVFAIL.
test "forward native stale follows transport exhaustion without replacement" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    harness.zones[0].cache = .{ .capacity = 1 };
    harness.zones[0].serve_stale_s = 300;
    try harness.start();
    const client = try harness.client(system.SOCK.DGRAM);
    defer _ = system.close(client);
    var input: [512]u8 = undefined;
    var upstream: [512]u8 = undefined;
    var response: [512]u8 = undefined;
    var output: [512]u8 = undefined;
    const bytes = try query(&input, 23, "stale.example.");
    try send(client, bytes);
    const request = try harness.request(&upstream);
    try send(harness.peer.?, try answer(&response, request.bytes, 0, 1));
    _ = try harness.receive(client, &output);
    const entry = &harness.service.pipeline.zones[0].cache.positive.entries[0];
    try testing.expectEqual(5, entry.lifetime_s);
    const stored = entry.bytes.?.ptr;
    entry.inserted_s = (try runtime.now()) - entry.lifetime_s;
    harness.zones[0].read_timeout_s = 0.001;
    try send(client, bytes);
    const length = try harness.receive(client, &output);
    const packet = try testing.allocator.create(wire.Packet);
    defer testing.allocator.destroy(packet);
    try packet.parse(output[0..length]);
    try testing.expectEqual(1, packet.header.counts[1]);
    try testing.expectEqual(30, packet.records[0].ttl_s);
    try testing.expectEqual(stored, entry.bytes.?.ptr);
    try testing.expectEqual(null, harness.service.pipeline.zones[0].cache.denial.entries[0].bytes);
    try harness.stop();
}

// SPEC §3.6: idle expiry closes the peer before a new session generation.
test "forward native configured idle expiry closes reused socket" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    harness.zones[0].conn_expire_s = 0.001;
    try harness.start();
    const client = try harness.client(system.SOCK.DGRAM);
    defer _ = system.close(client);
    var input: [512]u8 = undefined;
    var upstream: [512]u8 = undefined;
    var response: [512]u8 = undefined;
    var output: [512]u8 = undefined;
    const bytes = try query(&input, 24, "idle.example.");
    try send(client, bytes);
    const request = try harness.request(&upstream);
    const generation = harness.service.forward.sessions[request.session].generation;
    try send(harness.peer.?, try answer(&response, request.bytes, 0, 1));
    _ = try harness.receive(client, &output);
    // Runtime timer readiness, not a sleep, supplies the expiry synchronization.
    for (0..32) |_| {
        if (harness.service.forward.sessions[request.session].state == .vacant) break;
        try testing.expect(try harness.service.step());
    }
    try testing.expectEqual(.vacant, harness.service.forward.sessions[request.session].state);
    try testing.expectEqual(0, system.recv(harness.peer.?, &upstream, upstream.len, 0));
    _ = system.close(harness.peer.?);
    harness.peer = null;
    try send(client, bytes);
    const next = try harness.request(&upstream);
    try testing.expect(harness.service.forward.sessions[next.session].generation > generation);
    try send(harness.peer.?, try answer(&response, next.bytes, 0, 1));
    _ = try harness.receive(client, &output);
    try harness.stop();
}

// SPEC §1: active sessions, original requests,.
// reserved responses survive stop barriers in every phase.
test "forward native cancellation in each upstream phase" {
    for ([_]@FieldType(runtime.forward.Session, "state"){
        .connecting, .writing, .read_prefix, .read_body,
    }) |wanted| {
        var harness: Harness = undefined;
        try harness.init();
        defer harness.deinit();
        try harness.start();
        const client = try harness.client(system.SOCK.DGRAM);
        defer _ = system.close(client);
        var input: [512]u8 = undefined;
        var upstream: [512]u8 = undefined;
        try send(client, try query(&input, 25, "cancel.example."));
        if (wanted == .read_body) {
            _ = try harness.request(&upstream);
            try send(harness.peer.?, &.{ 0, 32, 1 });
        }
        const index = try harness.phase(wanted);
        const transaction = harness.service.forward.sessions[index].transaction.?;
        const generation = harness.service.forward.sessions[index].generation;
        try harness.stop();
        try testing.expect(!harness.service.proctor.pending());
        try testing.expectEqual(.active, harness.service.forward.transactions[transaction].state);
        try testing.expectEqual(generation, harness.service.forward.sessions[index].generation);
    }
}

// SPEC §1: the thirty-third transaction receives an uncached local failure, not stale or failover.
test "forward native pool exhaustion retains thirty-two owned requests" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    harness.zones[0].cache = .{ .capacity = 1 };
    harness.zones[0].serve_stale_s = 300;
    try harness.start();
    var clients: [33]?system.fd_t = @splat(null);
    defer for (clients) |client| {
        if (client) |descriptor| _ = system.close(descriptor);
    };
    var input: [512]u8 = undefined;
    var output: [512]u8 = undefined;
    for (&clients, 0..) |*client, index| {
        client.* = try harness.client(system.SOCK.DGRAM);
        try send(client.*.?, try query(&input, @intCast(index), "pool.example."));
    }
    const length = try harness.receive(clients[32].?, &output);
    try testing.expectEqual(32, (try wire.Header.decode(output[0..length])).id);
    try testing.expectEqual(2, (try wire.Header.decode(output[0..length])).bits & 15);
    for (&harness.service.forward.transactions, 0..) |*transaction, index| {
        try testing.expectEqual(.active, transaction.state);
        try testing.expectEqual(
            index,
            (try wire.Header.decode(transaction.input[0..transaction.length])).id,
        );
        try testing.expectEqual(1, transaction.cursor);
        const destination = transaction.destination;
        if (builtin.os.tag == .linux) {
            try testing.expectEqual(.reserved, harness.service.responses[destination.index].state);
        } else {
            try testing.expectEqual(.reserved, harness.service.responses[destination.index].state);
            try testing.expect(harness.service.responses[destination.index].listener != null);
        }
    }
    try testing.expectEqual(null, harness.service.pipeline.zones[0].cache.denial.entries[0].bytes);
    try harness.stop();
    try testing.expect(!harness.service.proctor.pending());
}

// SPEC §§1, 3.7: actual descriptor exhaustion is local and leaves both cache banks unchanged.
test "forward native socket resource exhaustion stays uncached" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    harness.zones[0].cache = .{ .capacity = 1 };
    harness.zones[0].upstreams = &harness.upstreams;
    try harness.start();
    const client = try harness.client(system.SOCK.DGRAM);
    defer _ = system.close(client);
    var input: [512]u8 = undefined;
    var output: [512]u8 = undefined;
    const bytes = try query(&input, 26, "quota.example.");
    var previous: system.rlimit = undefined;
    try testing.expectEqual(0, system.getrlimit(.NOFILE, &previous));
    const limited: system.rlimit = .{ .cur = 0, .max = previous.max };
    try testing.expectEqual(0, system.setrlimit(.NOFILE, &limited));
    defer testing.expectEqual(0, system.setrlimit(.NOFILE, &previous)) catch
        @panic("failed to restore descriptor quota");
    try send(client, bytes);
    const length = try harness.receive(client, &output);
    try testing.expectEqual(2, (try wire.Header.decode(output[0..length])).bits & 15);
    try testing.expectEqual(null, harness.service.pipeline.zones[0].cache.denial.entries[0].bytes);
    try testing.expectEqual(1, harness.service.forward.transactions[0].cursor);
    for (&harness.service.forward.sessions) |*session|
        try testing.expectEqual(.vacant, session.state);
    try testing.expectEqual(0, system.setrlimit(.NOFILE, &previous));
    try harness.stop();
}

fn expansionAnswer(output: []u8, request: []const u8) ![]const u8 {
    const packet = try testing.allocator.create(wire.Packet);
    defer testing.allocator.destroy(packet);
    try packet.parse(request);
    var parsed: runtime.pipeline.resolver.Request = undefined;
    try parsed.init(packet);
    var encoder: wire.Encoder = undefined;
    try encoder.init(output[2..], &.{ .id = packet.header.id, .bits = 0x8500 });
    try encoder.question(&parsed.name, parsed.kind, parsed.class);
    var text: [253]u8 = @splat('a');
    for ([_]usize{ 63, 127, 191 }) |index| text[index] = '.';
    var owner: wire.Name = undefined;
    try owner.fromText(&text);
    for (0..300) |_| {
        const record: wire.Record = .{
            .owner = 0,
            .kind = 1,
            .class = 1,
            .ttl_s = 30,
            .data_start = 0,
            .data_end = 0,
            .section = .answer,
        };
        const offset = try encoder.beginRecord(&owner, &record);
        try encoder.bytes(&.{ 192, 0, 2, 1 });
        encoder.endRecord(offset);
    }
    const record: wire.Record = .{
        .owner = 0,
        .kind = 65400,
        .class = 1,
        .ttl_s = 30,
        .data_start = 0,
        .data_end = 0,
        .section = .answer,
    };
    const offset = try encoder.beginRecord(&parsed.name, &record);
    const padding: [17000]u8 = @splat(0);
    try encoder.bytes(&padding);
    encoder.endRecord(offset);
    const bytes = try encoder.finish();
    try wire.framePrefix(output, bytes.len);
    return output[0 .. bytes.len + 2];
}

// SPEC §3.9: rotation can move first owner occurrences beyond the encoder dictionary range.
test "forward native rotation encoding failure never publishes or serves stale" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    harness.zones[0].cache = .{ .capacity = 1 };
    harness.zones[0].serve_stale_s = 300;
    harness.zones[0].rotate = true;
    try harness.start();
    const client = try harness.client(system.SOCK.STREAM);
    defer _ = system.close(client);
    var input: [512]u8 = undefined;
    var upstream: [512]u8 = undefined;
    var response: [65537]u8 = undefined;
    var output: [65537]u8 = undefined;
    const bytes = try query(input[2..], 27, "expansion.example.");
    try wire.framePrefix(&input, bytes.len);
    try send(client, input[0 .. bytes.len + 2]);
    const first = try harness.request(&upstream);
    try send(harness.peer.?, try answer(&response, first.bytes, 0, 1));
    _ = try harness.frame(client, &output);
    const entry = &harness.service.pipeline.zones[0].cache.positive.entries[0];
    const stored = entry.bytes.?.ptr;
    entry.inserted_s = (try runtime.now()) - entry.lifetime_s;
    try send(client, input[0 .. bytes.len + 2]);
    const next = try harness.request(&upstream);
    try send(harness.peer.?, try expansionAnswer(&response, next.bytes));
    const received = try harness.frame(client, &output);
    try testing.expectEqual(2, (try wire.Header.decode(received)).bits & 15);
    try testing.expectEqual(0, (try wire.Header.decode(received)).counts[1]);
    try testing.expectEqual(stored, entry.bytes.?.ptr);
    try testing.expectEqual(null, harness.service.pipeline.zones[0].cache.denial.entries[0].bytes);
    try harness.stop();
}

// SPEC §3.9; RFC 6891 §6.1.3: complete extended RCODEs require client OPT and never cache.
test "forward native extended RCODE exclusions and client OPT" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    harness.zones[0].cache = .{ .capacity = 1 };
    harness.zones[0].upstreams = &harness.upstreams;
    try harness.start();
    const client = try harness.client(system.SOCK.DGRAM);
    defer _ = system.close(client);
    var input: [512]u8 = undefined;
    var upstream: [512]u8 = undefined;
    var response: [512]u8 = undefined;
    var output: [512]u8 = undefined;
    const packet = try testing.allocator.create(wire.Packet);
    defer testing.allocator.destroy(packet);
    for (0..2) |with_opt| {
        const bytes = if (with_opt == 0)
            try query(&input, 53, "rcode.example.")
        else
            try ednsQuery(&input, 53, "rcode.example.", 99);
        try send(client, bytes);
        const request = try harness.request(&upstream);
        const framed = try answer(&response, request.bytes, 0, 0);
        @memcpy(response[framed.len..][0..11], &[_]u8{ 0, 0, 41, 4, 208, 1, 0, 0, 0, 0, 0 });
        wire.put(u16, response[12..14], 1);
        try wire.framePrefix(&response, framed.len - 2 + 11);
        try send(harness.peer.?, response[0 .. framed.len + 11]);
        const length = try harness.receive(client, &output);
        try packet.parse(output[0..length]);
        if (with_opt == 0) {
            try testing.expectEqual(2, packet.header.bits & 15);
            try testing.expectEqual(null, packet.opt);
        } else {
            try testing.expectEqual(0, packet.header.bits & 15);
            try testing.expectEqual(1, packet.records[packet.opt.?].ttl_s >> 24);
            try testing.expectEqual(99, packet.bytes[packet.records[packet.opt.?].data_start + 4]);
        }
        try emptyCache(&harness);
    }
    try harness.stop();
}

// SPEC §3.6: partial prefix and body bytes consume one absolute response deadline.
test "forward native slow prefix and body do not extend deadline" {
    for ([_][]const u8{ &.{0}, &.{ 0, 32, 1, 2, 3 } }) |fragment| {
        var harness: Harness = undefined;
        try harness.init();
        defer harness.deinit();
        harness.zones[0].read_timeout_s = 0.02;
        try harness.start();
        const client = try harness.client(system.SOCK.DGRAM);
        defer _ = system.close(client);
        var input: [512]u8 = undefined;
        var upstream: [512]u8 = undefined;
        var output: [512]u8 = undefined;
        try send(client, try query(&input, 28, "slow.example."));
        const request = try harness.request(&upstream);
        const deadline_ns = harness.service.forward.sessions[request.session].deadline_ns;
        try send(harness.peer.?, fragment);
        for (0..16) |_| {
            try testing.expect(try harness.service.step());
            if (harness.service.forward.sessions[request.session].offset == fragment.len) break;
        }
        try testing.expectEqual(
            fragment.len,
            harness.service.forward.sessions[request.session].offset,
        );
        try testing.expectEqual(
            deadline_ns,
            harness.service.forward.sessions[request.session].deadline_ns,
        );
        const length = try harness.receive(client, &output);
        try testing.expectEqual(2, (try wire.Header.decode(output[0..length])).bits & 15);
        try harness.stop();
    }
}

// SPEC §1: both linked slots retire, including cancellation acknowledgements that arrive last.
test "forward linked pair permutations late completions and wide indices" {
    for (0..4) |order| {
        var first: runtime.proctor.Ownership = .{};
        var second: runtime.proctor.Ownership = .{};
        const one = try first.arm(287);
        const two = try second.arm(288);
        first.cancel();
        second.cancel();
        switch (order) {
            0, 1 => {
                if (order == 0) {
                    try first.complete(one, .terminal);
                    try second.complete(two, .terminal);
                } else {
                    try second.complete(two, .terminal);
                    try first.complete(one, .terminal);
                }
                try testing.expect(!runtime.forward.retired(&first, &second));
                try first.complete(one, .cancellation);
            },
            2 => {
                try first.complete(one, .cancellation);
                try first.complete(one, .terminal);
                try second.complete(two, .terminal);
            },
            3 => {
                try second.complete(two, .cancellation);
                try second.complete(two, .terminal);
                try first.complete(one, .terminal);
            },
            else => unreachable,
        }
        try testing.expect(!runtime.forward.retired(&first, &second));
        if (order == 3) {
            try first.complete(one, .cancellation);
        } else try second.complete(two, .cancellation);
        try testing.expect(runtime.forward.retired(&first, &second));
        const next = try first.arm(287);
        try testing.expectError(error.InvalidCompletion, first.complete(one, .terminal));
        try testing.expect(!runtime.forward.retired(&first, &second));
        try first.complete(next, .terminal);
        try testing.expectError(error.InvalidCompletion, second.complete(two, .terminal));
    }
}

// SPEC §3.6: TCP peer association refers to a configured endpoint.
// connection lifetime, not an injected datagram.
test "forward peer association and unsupported membership" {
    const forward = try testing.allocator.create(runtime.forward.Forward);
    defer testing.allocator.destroy(forward);
    const pipeline = try testing.allocator.create(runtime.pipeline.Pipeline);
    defer testing.allocator.destroy(pipeline);
    var zones = [_]config.Zone{
        .{
            .suffix = ".",
            .cache = null,
            .upstreams = &.{.{ .address = "127.0.0.1:53", .force_tcp = true }},
        },
        .{ .suffix = "tls.", .cache = null, .upstreams = &.{.{
            .address = "127.0.0.1:53",
            .force_tcp = true,
            .tls = .{ .server_name = "dns.example" },
        }} },
        .{
            .suffix = "hostname.",
            .cache = null,
            .upstreams = &.{.{ .address = "dns.example:53", .force_tcp = true }},
        },
    };
    const settings: config.Config = .{ .zones = &zones };
    try pipeline.init(testing.allocator, testing.io, &settings);
    defer pipeline.deinit();
    try forward.init(testing.io, &settings);
    try testing.expectEqual(.supported, forward.support[0]);
    try testing.expectEqual(.supported, forward.support[1]);
    try testing.expectEqual(.unsupported, forward.support[2]);
    var input: [512]u8 = undefined;
    const bytes = try query(&input, 29, "peer.example.");
    const transaction = forward.admit(bytes, 0, &.{
        .index = 0,
        .generation = 1,
        .transport = .tcp,
    }).?;
    const selected = forward.select(transaction, 0).?;
    try forward.prepare(selected.session, pipeline);
    const session = &forward.sessions[selected.session];
    const request = session.output[2..session.length];
    const response = try answer(&session.input, request, 0, 1);
    session.length = @intCast(response.len);
    session.generation = 1;
    try testing.expect(!forward.admitted(selected.session, .{
        .endpoint = 1,
        .generation = 1,
    }, pipeline));
    try testing.expect(!forward.admitted(selected.session, .{
        .endpoint = 0,
        .generation = 2,
    }, pipeline));
    try testing.expect(forward.admitted(selected.session, .{
        .endpoint = 0,
        .generation = 1,
    }, pipeline));
}

// SPEC §3.1: the longest suffix selects its upstream. The hostname root remains unresolved.
test "forward native longest zone selects configured endpoint" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    harness.upstreams[0].address = "dns.example:853";
    harness.settings.zones = &harness.zones;
    try harness.start();
    const client = try harness.client(system.SOCK.DGRAM);
    defer _ = system.close(client);
    var input: [512]u8 = undefined;
    var upstream: [512]u8 = undefined;
    var response: [512]u8 = undefined;
    var output: [512]u8 = undefined;
    try send(client, try query(&input, 30, "routed.example."));
    const request = try harness.request(&upstream);
    try testing.expectEqual(16, harness.service.forward.sessions[request.session].endpoint);
    try send(harness.peer.?, try answer(&response, request.bytes, 0, 1));
    const length = try harness.receive(client, &output);
    try testing.expectEqual(1, (try wire.Header.decode(output[0..length])).counts[1]);
    try send(client, try query(&input, 31, "unsupported.invalid."));
    const failed = try harness.receive(client, &output);
    try testing.expectEqual(2, (try wire.Header.decode(output[0..failed])).bits & 15);
    try harness.stop();
}

// RFC 1035 §4.2.2: short frames, zero reads, and oversized completions cannot advance offsets.
test "forward bounded partial receive and transmit offsets" {
    const forward = try testing.allocator.create(runtime.forward.Forward);
    defer testing.allocator.destroy(forward);
    const session = &forward.sessions[0];
    session.transport = .tcp;
    session.prefix();
    session.input[0..2].* = .{ 0, 11 };
    try testing.expectEqual(.failed, session.received(2));
    session.prefix();
    try testing.expectEqual(.failed, session.received(0));
    try testing.expectEqual(.progress, session.received(1));
    try testing.expectEqual(.failed, session.received(2));
    try testing.expectEqual(1, session.offset);
    session.state = .writing;
    session.offset = 0;
    session.length = 12;
    try testing.expectEqual(.progress, forward.sent(0, 1, 0));
    try testing.expectEqual(.failed, forward.sent(0, 12, 0));
    try testing.expectEqual(1, session.offset);
    session.prefix();
    session.input[0..2].* = .{ 255, 255 };
    try testing.expectEqual(.progress, session.received(2));
    try testing.expectEqual(65537, session.length);
    try testing.expectEqual(.frame, session.received(65535));
}

fn emptyCache(harness: *Harness) !void {
    const cache = &harness.service.pipeline.zones[0].cache;
    try testing.expectEqual(null, cache.positive.entries[0].bytes);
    try testing.expectEqual(null, cache.denial.entries[0].bytes);
}

fn extraQuestion(output: []u8, request: []const u8) ![]const u8 {
    const packet = try testing.allocator.create(wire.Packet);
    defer testing.allocator.destroy(packet);
    try packet.parse(request);
    var parsed: runtime.pipeline.resolver.Request = undefined;
    try parsed.init(packet);
    var encoder: wire.Encoder = undefined;
    try encoder.init(output[2..], &.{ .id = packet.header.id, .bits = 0x8500 });
    try encoder.question(&parsed.name, parsed.kind, parsed.class);
    try encoder.question(&parsed.name, parsed.kind, parsed.class);
    const bytes = try encoder.finish();
    try wire.framePrefix(output, bytes.len);
    return output[0 .. bytes.len + 2];
}

test {
    if (builtin.os.tag == .macos) _ = Darwin;
    if (builtin.os.tag == .linux) _ = LinuxPair;
    if (builtin.os.tag == .linux) _ = LinuxSubmittedTeardown;
}

// #1: this Linux host disables IPv6. Native Linux IPv6 exchange coverage remains unproved.
const Darwin = struct {
    // SPEC §§1.3, 3.6: injected SO_ERROR resource failures use real kqueue dispatch.
    // These failures never advance the upstream sequence.
    test "forward Darwin injected connect resources preserve stale cache without retry" {
        var harness: Harness = undefined;
        try harness.init();
        defer harness.deinit();
        harness.zones[0].cache = .{ .capacity = 1 };
        harness.zones[0].serve_stale_s = 300;
        harness.zones[0].upstreams = &harness.upstreams;
        try harness.start();
        const client = try harness.client(system.SOCK.DGRAM);
        defer _ = system.close(client);
        var input: [512]u8 = undefined;
        var upstream: [512]u8 = undefined;
        var response: [512]u8 = undefined;
        var output: [512]u8 = undefined;
        const bytes = try query(&input, 35, "connect-resource.example.");
        try send(client, bytes);
        const first = try harness.request(&upstream);
        try send(harness.peer.?, try answer(&response, first.bytes, 0, 1));
        _ = try harness.receive(client, &output);
        const entry = &harness.service.pipeline.zones[0].cache.positive.entries[0];
        const stored = entry.bytes.?.ptr;
        entry.inserted_s = (try runtime.now()) - entry.lifetime_s;
        harness.service.forward.sessions[first.session].deadline_ns = try runtime.nowNs();
        const stored_length = entry.bytes.?.len;
        @memcpy(response[0..stored_length], entry.bytes.?);
        for ([_]system.E{ .NOMEM, .NOBUFS, .MFILE, .NFILE }) |failure| {
            for ([_]enum { socket, syscall }{ .socket, .syscall }) |source| {
                harness.service.upstreams.test_connect_error = switch (source) {
                    .socket => .{ .socket = failure },
                    .syscall => .{ .syscall = failure },
                };
                try send(client, bytes);
                const index = try harness.phase(.connecting);
                try connectResult(&harness);
                // Retry mutations fail here, before any response wait.
                try testing.expectEqual(1, harness.service.forward.transactions[0].cursor);
                try testing.expectEqual(.vacant, harness.service.forward.sessions[index].state);
                const length = try harness.receive(client, &output);
                const header = try wire.Header.decode(output[0..length]);
                try testing.expectEqual(2, header.bits & 15);
                try testing.expectEqual(0, header.counts[1]);
                try testing.expectEqual(stored, entry.bytes.?.ptr);
                try testing.expectEqualSlices(u8, response[0..stored_length], entry.bytes.?);
                try testing.expectEqual(
                    null,
                    harness.service.pipeline.zones[0].cache.denial.entries[0].bytes,
                );
            }
        }
        try harness.stop();
    }

    // SPEC §3.6: injected refusal and getsockopt failure still advance the configured sequence.
    test "forward Darwin injected connect transport failures retry" {
        for ([_]enum { refusal, syscall }{ .refusal, .syscall }) |source| {
            var harness: Harness = undefined;
            try harness.init();
            defer harness.deinit();
            harness.zones[0].upstreams = &harness.upstreams;
            try harness.start();
            const client = try harness.client(system.SOCK.DGRAM);
            defer _ = system.close(client);
            var input: [512]u8 = undefined;
            harness.service.upstreams.test_connect_error = switch (source) {
                .refusal => .{ .socket = .CONNREFUSED },
                .syscall => .{ .syscall = .BADF },
            };
            try send(client, try query(&input, 36, "connect-retry.example."));
            _ = try harness.phase(.connecting);
            try connectResult(&harness);
            try testing.expectEqual(2, harness.service.forward.transactions[0].cursor);
            try testing.expectEqual(.active, harness.service.forward.transactions[0].state);
            try harness.stop();
        }
    }

    // SPEC §3.6: injected zero SO_ERROR reaches writes through the actual driver readiness path.
    test "forward Darwin injected connect success writes the request" {
        var harness: Harness = undefined;
        try harness.init();
        defer harness.deinit();
        try harness.start();
        const client = try harness.client(system.SOCK.DGRAM);
        defer _ = system.close(client);
        var input: [512]u8 = undefined;
        var upstream: [512]u8 = undefined;
        var response: [512]u8 = undefined;
        var output: [512]u8 = undefined;
        harness.service.upstreams.test_connect_error = .{ .socket = .SUCCESS };
        try send(client, try query(&input, 37, "connect-success.example."));
        const index = try harness.phase(.connecting);
        try connectResult(&harness);
        try testing.expectEqual(.writing, harness.service.forward.sessions[index].state);
        try testing.expectEqual(1, harness.service.forward.transactions[0].cursor);
        const request = try harness.request(&upstream);
        try send(harness.peer.?, try answer(&response, request.bytes, 0, 1));
        const length = try harness.receive(client, &output);
        try testing.expectEqual(1, (try wire.Header.decode(output[0..length])).counts[1]);
        try harness.stop();
    }

    fn connectResult(harness: *Harness) !void {
        for (0..128) |_| {
            if (harness.service.upstreams.test_connect_error == null) return;
            try testing.expect(try harness.service.step());
        }
        return error.ConnectResultNotConsumed;
    }

    // SPEC §§3.6, 5.1: literal IPv6 upstreams retain their configured family and port.
    test "forward Darwin native literal IPv6 upstream" {
        var harness: Harness = undefined;
        try harness.init();
        defer harness.deinit();
        _ = system.close(harness.listener.?);
        harness.listener = null;
        try harness.upstream_address.parse("[::1]:1");
        const ip: *system.sockaddr.in6 = @ptrCast(&harness.upstream_address.storage);
        ip.port = 0;
        harness.listener = try harness.upstream_address.bind(system.SOCK.STREAM);
        try testing.expectEqual(0, system.getsockname(
            harness.listener.?,
            @ptrCast(&harness.upstream_address.storage),
            &harness.upstream_address.length,
        ));
        harness.upstreams[0].address = try std.fmt.bufPrint(&harness.upstream_text, "[::1]:{d}", .{
            std.mem.bigToNative(u16, ip.port),
        });
        try harness.start();
        const client = try harness.client(system.SOCK.DGRAM);
        defer _ = system.close(client);
        var input: [512]u8 = undefined;
        var upstream: [512]u8 = undefined;
        var response: [512]u8 = undefined;
        var output: [512]u8 = undefined;
        try send(client, try query(&input, 32, "ipv6.example."));
        const request = try harness.request(&upstream);
        try send(harness.peer.?, try answer(&response, request.bytes, 0, 1));
        const length = try harness.receive(client, &output);
        try testing.expectEqual(1, (try wire.Header.decode(output[0..length])).counts[1]);
        try harness.stop();
    }
};

// SPEC §3.9: mandatory upstream OPT expansion can fail locally before a socket exchange starts.
test "forward native query encoding failure is uncached without attempts" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    harness.zones[0].cache = .{ .capacity = 1 };
    harness.zones[0].upstreams = &harness.upstreams;
    try harness.start();
    const client = try harness.client(system.SOCK.STREAM);
    defer _ = system.close(client);
    var input: [65537]u8 = undefined;
    var output: [512]u8 = undefined;
    var encoder: wire.Encoder = undefined;
    var name: wire.Name = undefined;
    try name.fromText("oversize.example.");
    try encoder.init(input[2..], &.{ .id = 33, .bits = 0x100 });
    try encoder.question(&name, 1, 1);
    const record: wire.Record = .{
        .owner = 0,
        .kind = 65400,
        .class = 1,
        .ttl_s = 0,
        .data_start = 0,
        .data_end = 0,
        .section = .additional,
    };
    const offset = try encoder.beginRecord(&name, &record);
    const padding: [65535]u8 = @splat(0);
    try encoder.bytes(padding[0 .. 65535 - encoder.cursor]);
    encoder.endRecord(offset);
    const bytes = try encoder.finish();
    try wire.framePrefix(&input, bytes.len);
    try harness.sendClient(client, &input);
    const received = try harness.frame(client, &output);
    try testing.expectEqual(2, (try wire.Header.decode(received)).bits & 15);
    try emptyCache(&harness);
    for (&harness.service.forward.sessions) |*session| {
        try testing.expectEqual(.vacant, session.state);
        try testing.expectEqual(0, session.generation);
    }
    try testing.expectEqual(1, harness.service.forward.transactions[0].cursor);
    try harness.stop();
}

// SPEC §1: fixture startup failures release prepared storage and descriptors on Linux and Darwin.
test "forward fixture pre-start error releases owned storage and listener" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const service = harness.service;
    const listener = harness.listener.?;
    // A control can omit release. This independent defer prevents a leak as the control signal.
    defer {
        if (harness.state == .released) {
            if (harness.allocator.allocated_bytes != harness.allocator.freed_bytes)
                harness.allocator.allocator().destroy(service);
        }
    }
    harness.listen[0] = "unresolved.invalid:53";
    try testing.expectError(error.UnresolvedListener, harness.start());
    try testing.expectEqual(.prepared, harness.state);
    harness.release();
    try testing.expectEqual(harness.allocator.allocated_bytes, harness.allocator.freed_bytes);
    try testing.expectEqual(-1, system.fcntl(listener, system.F.GETFD));
    try testing.expectEqual(system.E.BADF, std.posix.errno(@as(c_int, -1)));
}

fn linkedDeadline(harness: *Harness, index: u16) !void {
    const deadline_ns = harness.service.forward.sessions[index].deadline_ns;
    if (builtin.os.tag == .linux) {
        const ring = &harness.service.proctor.ring;
        const position = (ring.sq.sqe_tail -% 1) & ring.sq.mask;
        const entry = &ring.sq.sqes[position];
        try testing.expectEqual(std.os.linux.IORING_OP.LINK_TIMEOUT, entry.opcode);
        try testing.expectEqual(std.os.linux.IORING_TIMEOUT_ABS, entry.rw_flags);
        const timeout = harness.service.upstreams.operations[index].timeout;
        const timestamp = @as(u64, @intCast(timeout.sec)) * std.time.ns_per_s +
            @as(u64, @intCast(timeout.nsec));
        try testing.expectEqual(deadline_ns, timestamp);
    } else {
        try testing.expectEqual(deadline_ns, harness.service.upstreams.timer_deadline_ns.?);
    }
}

// SPEC §1.3: secure entropy failures stop startup before resource allocation or socket setup.
const Entropy = struct {
    failure: ?std.Io.RandomSecureError = null,
    secure_calls: u32 = 0,
    fallback_calls: u32 = 0,
    seed_bytes: usize = 0,

    fn secure(userdata: ?*anyopaque, buffer: []u8) std.Io.RandomSecureError!void {
        const self: *Entropy = @ptrCast(@alignCast(userdata.?));
        self.secure_calls += 1;
        self.seed_bytes = buffer.len;
        // Public fixture bytes are not real entropy. Partial failure also writes seed storage.
        @memset(buffer, 0x5a);
        if (self.failure) |failure| return failure;
    }

    fn fallback(userdata: ?*anyopaque, buffer: []u8) void {
        const self: *Entropy = @ptrCast(@alignCast(userdata.?));
        self.fallback_calls += 1;
        @memset(buffer, 0xa5);
    }
};

// SPEC §1.3: both backends reject unavailable or canceled secure entropy before startup I/O.
test "forward secure entropy startup errors precede allocation and sockets" {
    const service = try testing.allocator.create(runtime.Runtime);
    defer testing.allocator.destroy(service);
    var zones = [_]config.Zone{.{
        .suffix = ".",
        .upstreams = &.{.{ .address = "127.0.0.1:53", .force_tcp = true }},
        .cache = .{ .capacity = 1 },
    }};
    const settings: config.Config = .{ .zones = &zones };
    var vtable = testing.io.vtable.*;
    vtable.randomSecure = Entropy.secure;
    vtable.random = Entropy.fallback;
    for ([_]std.Io.RandomSecureError{ error.EntropyUnavailable, error.Canceled }) |failure| {
        var entropy: Entropy = .{ .failure = failure };
        const io: std.Io = .{ .userdata = &entropy, .vtable = &vtable };
        // A broken entropy guard reaches OutOfMemory, never a native listener or ring.
        var allocator = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
        try testing.expectError(failure, service.init(allocator.allocator(), io, &settings));
        try testing.expectEqual(1, entropy.secure_calls);
        try testing.expectEqual(std.Random.DefaultCsprng.secret_seed_length, entropy.seed_bytes);
        try testing.expectEqual(0, entropy.fallback_calls);
        try testing.expect(!allocator.has_induced_failure);
        try testing.expectEqual(0, allocator.allocated_bytes);
        try testing.expectEqual(allocator.allocated_bytes, allocator.freed_bytes);
        for (service.listeners) |listener| {
            try testing.expectEqual(null, listener.udp);
            try testing.expectEqual(null, listener.tcp);
        }
    }
}

// SPEC §§1.3, 3.6: the secure fixture seed supplies IDs without Io.random or query allocation.
test "forward secure entropy supplies deterministic upstream IDs without fallback" {
    const forward = try testing.allocator.create(runtime.forward.Forward);
    defer testing.allocator.destroy(forward);
    const pipeline = try testing.allocator.create(runtime.pipeline.Pipeline);
    defer testing.allocator.destroy(pipeline);
    var zones = [_]config.Zone{.{
        .suffix = ".",
        .cache = null,
        .upstreams = &.{.{ .address = "127.0.0.1:53", .force_tcp = true }},
    }};
    const settings: config.Config = .{ .zones = &zones };
    var allocator = testing.FailingAllocator.init(testing.allocator, .{});
    try pipeline.init(allocator.allocator(), testing.io, &settings);
    defer pipeline.deinit();
    allocator.fail_index = allocator.alloc_index;
    var entropy: Entropy = .{};
    var vtable = testing.io.vtable.*;
    vtable.randomSecure = Entropy.secure;
    vtable.random = Entropy.fallback;
    try forward.init(.{ .userdata = &entropy, .vtable = &vtable }, &settings);
    try testing.expectEqual(1, entropy.secure_calls);
    try testing.expectEqual(std.Random.DefaultCsprng.secret_seed_length, entropy.seed_bytes);
    try testing.expectEqual(0, entropy.fallback_calls);
    var expected: std.Random.DefaultCsprng = .init(@splat(0x5a));
    var input: [512]u8 = undefined;
    const bytes = try query(&input, 17, "entropy.example.");
    const transaction = forward.admit(bytes, 0, &.{
        .index = 0,
        .generation = 1,
        .transport = .tcp,
    }).?;
    const selected = forward.select(transaction, 0).?;
    for (0..4) |_| {
        try forward.prepare(selected.session, pipeline);
        const session = &forward.sessions[selected.session];
        try testing.expectEqual(expected.random().int(u16), session.identifier);
        try testing.expectEqual(session.identifier, wire.integer(u16, session.output[2..4]));
    }
    try testing.expectEqual(1, entropy.secure_calls);
    try testing.expectEqual(0, entropy.fallback_calls);
    try testing.expect(!allocator.has_induced_failure);
}

const FragmentReader = struct {
    bytes: []const u8,
    fragment_bytes_max: usize,
    offset: usize = 0,
    deadline_ns: ?u64 = null,

    fn read(self: *FragmentReader, output: []u8, deadline_ns: u64) !usize {
        if (self.deadline_ns) |expected| {
            try testing.expectEqual(expected, deadline_ns);
        } else self.deadline_ns = deadline_ns;
        const count = @min(output.len, self.fragment_bytes_max, self.bytes.len - self.offset);
        @memcpy(output[0..count], self.bytes[self.offset..][0..count]);
        self.offset += count;
        return count;
    }
};

// SPEC §3.9: deterministic one-byte reads split both prefix and body without a timing dependency.
test "forward peer reader fragmented prefix body and queued frames" {
    const frames = [_]u8{ 0, 12 } ++ [_]u8{1} ** 12 ++ [_]u8{ 0, 12 } ++ [_]u8{2} ** 12;
    var reader: FragmentReader = .{ .bytes = &frames, .fragment_bytes_max = 1 };
    var output: [64]u8 = undefined;
    const first = peerFrame(&reader, &output) catch null;
    try testing.expect(first != null);
    try testing.expectEqualSlices(u8, frames[2..14], first.?);
    try testing.expectEqual(14, reader.offset);
    reader.deadline_ns = null;
    const second = peerFrame(&reader, &output) catch null;
    try testing.expect(second != null);
    try testing.expectEqualSlices(u8, frames[16..28], second.?);
    try testing.expectEqual(frames.len, reader.offset);
}

// SPEC §3.9: a reader limits each receive even when two complete frames are available.
test "forward peer reader coalesced frames remain queued" {
    const frames = [_]u8{ 0, 12 } ++ [_]u8{1} ** 12 ++ [_]u8{ 0, 12 } ++ [_]u8{2} ** 12;
    var reader: FragmentReader = .{ .bytes = &frames, .fragment_bytes_max = frames.len };
    var output: [64]u8 = undefined;
    const first = peerFrame(&reader, &output) catch null;
    try testing.expect(first != null);
    try testing.expectEqual(14, reader.offset);
    reader.deadline_ns = null;
    try testing.expectEqualSlices(u8, frames[16..28], try peerFrame(&reader, &output));
    try testing.expectEqual(frames.len, reader.offset);
}

// SPEC §3.9: EOF, invalid DNS lengths, and output bounds fail without an unbounded read.
test "forward peer reader rejects EOF and invalid bounds" {
    var output: [64]u8 = undefined;
    for ([_][]const u8{ &.{}, &.{0}, &.{ 0, 12, 1 } }) |bytes| {
        var reader: FragmentReader = .{ .bytes = bytes, .fragment_bytes_max = 1 };
        try testing.expectError(error.Closed, peerFrame(&reader, &output));
    }
    for ([_][]const u8{ &.{ 0, 0 }, &.{ 0, 11 } }) |bytes| {
        var reader: FragmentReader = .{ .bytes = bytes, .fragment_bytes_max = 1 };
        try testing.expectError(error.ShortFrame, peerFrame(&reader, &output));
    }
    var reader: FragmentReader = .{ .bytes = &.{ 255, 255 }, .fragment_bytes_max = 1 };
    try testing.expectError(error.ShortBuffer, peerFrame(&reader, output[0..1]));
    try testing.expectEqual(0, reader.offset);
    try testing.expectError(error.ShortBuffer, peerFrame(&reader, &output));
    try testing.expectEqual(2, reader.offset);
    var peer: PeerReader = .{ .descriptor = -1 };
    try testing.expectError(error.PeerReadDeadline, peer.read(&output, 0));
}

// Synthetic target CQEs model ownership transitions, not kernel completion order or short sends.
// Real registered socketpairs keep every subsequent driver SQE valid, including assertion cleanup.
const LinuxPair = struct {
    const linux = std.os.linux;
    const orders = [_]Order{
        .io_first,
        .timeout_first,
        .targets_first,
        .acknowledgements_first,
        .io_barrier_last,
        .timeout_barrier_last,
    };
    const Event = enum { io, timeout, io_cancel, timeout_cancel };
    const Order = enum {
        io_first,
        timeout_first,
        targets_first,
        acknowledgements_first,
        io_barrier_last,
        timeout_barrier_last,

        fn events(self: Order) []const Event {
            return switch (self) {
                .io_first => &.{ .io, .timeout },
                .timeout_first => &.{ .timeout, .io },
                .targets_first => &.{ .io, .timeout, .io_cancel, .timeout_cancel },
                .acknowledgements_first => &.{ .io_cancel, .timeout_cancel, .timeout, .io },
                .io_barrier_last => &.{ .timeout_cancel, .timeout, .io, .io_cancel },
                .timeout_barrier_last => &.{ .io_cancel, .io, .timeout, .timeout_cancel },
            };
        }
    };
    const Snapshot = struct {
        state: @FieldType(runtime.forward.Session, "state"),
        offset: u32,
        length: u32,
        deadline_ns: u64,
        input_hash: u64,
        output_hash: u64,
        client_hash: u64,
    };
    const Fixture = struct {
        service: *runtime.Runtime,
        peers: [2]linux.fd_t,
        session: u16,
        slot: u32,
        settings: config.Config,
        zones: [1]config.Zone,

        fn init(self: *Fixture) !void {
            self.service = try testing.allocator.create(runtime.Runtime);
            errdefer testing.allocator.destroy(self.service);
            const service = self.service;
            service.state = .running;
            service.io = testing.io;
            service.listener_count = 0;
            self.zones = .{.{
                .suffix = ".",
                .upstreams = &.{.{ .address = "127.0.0.1:53", .force_tcp = true }},
                .cache = .{ .capacity = 1 },
                .read_timeout_s = 60,
            }};
            self.settings = .{ .zones = &self.zones };
            try service.forward.init(testing.io, &self.settings);
            service.upstreams.init();
            try service.pipeline.init(testing.allocator, testing.io, &self.settings);
            errdefer service.pipeline.deinit();
            try service.proctor.init();
            errdefer service.proctor.deinit();
            try service.proctor.ring.register_files_sparse(192);
            for (&service.clients) |*client| {
                client.state = .vacant;
                client.generation = 0;
            }
            for (&service.responses) |*reservation| reservation.state = .free;
            service.clients[0].reset();
            service.clients[0].phase = .waiting;
            // This Unix-socket fixture bypasses IP peer lookup and normal query admission.
            service.clients[0].observation = .{
                .client = null,
                .protocol = .tcp,
                .started_ns = try runtime.nowNs(),
            };
            @memset(&service.clients[0].output, 0xa5);
            try self.admit();
            const upstream_pair = try socketPair();
            defer _ = linux.close(upstream_pair[0]);
            errdefer _ = linux.close(upstream_pair[1]);
            const client_pair = try socketPair();
            defer _ = linux.close(client_pair[0]);
            errdefer _ = linux.close(client_pair[1]);
            self.peers = .{ upstream_pair[1], client_pair[1] };
            try service.proctor.ring.register_files_update(160 + self.session, upstream_pair[0..1]);
            try service.proctor.ring.register_files_update(32, client_pair[0..1]);
            const session = &service.forward.sessions[self.session];
            session.state = .writing;
            session.generation = 1;
            @memset(&session.input, 0);
            // No initial SQEs reach the kernel. These two owners model its borrowed pair.
            _ = try service.proctor.arm(self.slot);
            _ = try service.proctor.arm(self.slot + 1);
            const operation = &service.upstreams.operations[self.session];
            operation.kind = .pair;
            operation.result = null;
            operation.timeout_result = null;
            operation.peer = .{ .endpoint = session.endpoint, .generation = session.generation };
        }

        fn admit(self: *Fixture) !void {
            const service = self.service;
            var input: [512]u8 = undefined;
            const bytes = try query(&input, 0x1234, "pair.example.");
            const transaction = service.forward.admit(bytes, 0, &.{
                .index = 0,
                .generation = service.clients[0].generation,
                .transport = .tcp,
            }).?;
            self.session = service.forward.select(transaction, try runtime.nowNs()).?.session;
            self.slot = 225 + @as(u32, self.session) * 2;
            @memset(&service.forward.sessions[self.session].output, 0);
            try service.forward.prepare(self.session, &service.pipeline);
        }

        fn deinit(self: *Fixture) void {
            // This barrier also covers valid SQEs emitted before a failed test assertion.
            self.service.proctor.deinit();
            for (self.peers) |descriptor| _ = linux.close(descriptor);
            self.service.pipeline.deinit();
            testing.allocator.destroy(self.service);
            self.* = undefined;
        }

        fn response(self: *Fixture) !i32 {
            const session = &self.service.forward.sessions[self.session];
            const bytes = try answer(&session.input, session.output[2..session.length], 0, 1);
            session.state = .read_body;
            session.offset = 2;
            session.length = @intCast(bytes.len);
            return @intCast(bytes.len - 2);
        }

        fn snapshot(self: *const Fixture) Snapshot {
            const session = &self.service.forward.sessions[self.session];
            return .{
                .state = session.state,
                .offset = session.offset,
                .length = session.length,
                .deadline_ns = session.deadline_ns,
                .input_hash = std.hash.Wyhash.hash(0, &session.input),
                .output_hash = std.hash.Wyhash.hash(0, session.output[0..session.length]),
                .client_hash = std.hash.Wyhash.hash(0, &self.service.clients[0].output),
            };
        }

        fn preserved(self: *const Fixture, before: *const Snapshot) !void {
            const session = &self.service.forward.sessions[self.session];
            try testing.expectEqual(before.state, session.state);
            try testing.expectEqual(before.offset, session.offset);
            try testing.expectEqual(before.length, session.length);
            try testing.expectEqual(before.deadline_ns, session.deadline_ns);
            try testing.expectEqual(before.input_hash, std.hash.Wyhash.hash(0, &session.input));
            try testing.expectEqual(before.output_hash, std.hash.Wyhash.hash(
                0,
                session.output[0..session.length],
            ));
            try testing.expectEqual(.pair, self.service.upstreams.operations[self.session].kind);
            try testing.expectEqual(0, self.service.proctor.ring.sq_ready());
            try testing.expectEqual(1, self.service.proctor.ownership[self.slot].generation);
            try testing.expectEqual(1, self.service.proctor.ownership[self.slot + 1].generation);
            try testing.expectEqual(@as(?u16, 0), session.transaction);
            try testing.expectEqual(.active, self.service.forward.transactions[0].state);
            try testing.expectEqual(1, self.service.forward.transactions[0].cursor);
            try testing.expectEqual(.waiting, self.service.clients[0].phase);
            try testing.expectEqual(before.client_hash, std.hash.Wyhash.hash(
                0,
                &self.service.clients[0].output,
            ));
            try self.empty();
        }

        fn empty(self: *const Fixture) !void {
            const cache = &self.service.pipeline.zones[0].cache;
            try testing.expectEqual(null, cache.positive.entries[0].bytes);
            try testing.expectEqual(null, cache.denial.entries[0].bytes);
        }

        fn complete(self: *Fixture, event: Event, result: i32) !void {
            const slot = self.slot + @as(u32, switch (event) {
                .io, .io_cancel => 0,
                .timeout, .timeout_cancel => 1,
            });
            const cancellation = switch (event) {
                .io, .timeout => @as(u64, 0),
                .io_cancel, .timeout_cancel => runtime.proctor.cancel_bit,
            };
            const completion: linux.io_uring_cqe = .{
                .user_data = self.service.proctor.ownership[slot].token(slot) | cancellation,
                .res = result,
                .flags = 0,
            };
            // Proctor.next performs this exact ownership transition before Runtime dispatch.
            try self.service.proctor.ownership[slot].complete(
                completion.user_data,
                if (cancellation == 0) .terminal else .cancellation,
            );
            try self.service.upstreams.completed(self.service, &completion);
        }

        fn pair(self: *Fixture, order: Order, count: i32, timeout_result: i32) !void {
            const before = self.snapshot();
            const events = order.events();
            if (events.len == 4) {
                self.service.proctor.ownership[self.slot].cancel();
                self.service.proctor.ownership[self.slot + 1].cancel();
            }
            for (events, 0..) |event, index| {
                try self.complete(event, switch (event) {
                    .io => count,
                    .timeout => timeout_result,
                    .io_cancel => 0,
                    .timeout_cancel => negative(.NOENT),
                });
                if (index + 1 < events.len) try self.preserved(&before);
            }
        }

        fn close(
            self: *Fixture,
            disposition: @FieldType(runtime.forward.Session, "disposition"),
        ) !void {
            const service = self.service;
            try testing.expectEqual(.cancelling, service.forward.sessions[self.session].state);
            try testing.expectEqual(
                disposition,
                service.forward.sessions[self.session].disposition,
            );
            try testing.expectEqual(.close, service.upstreams.operations[self.session].kind);
            try testing.expectEqual(1, service.proctor.ring.sq_ready());
            try testing.expectEqual(2, service.proctor.ownership[self.slot].generation);
            try testing.expectEqual(.idle, service.proctor.ownership[self.slot + 1].state);
            const entry = &service.proctor.ring.sq.sqes[0];
            try testing.expectEqual(linux.IORING_OP.CLOSE, entry.opcode);
            try testing.expectEqual(161 + @as(i32, self.session), entry.splice_fd_in);
            try testing.expectEqual(.waiting, service.clients[0].phase);
            try self.empty();
            // Only this real CLOSE is queued. Its CQE releases a real registered socket.
            const completion = try service.proctor.next();
            try testing.expectEqual(
                service.proctor.ownership[self.slot].token(self.slot),
                completion.user_data,
            );
            try testing.expectEqual(0, completion.res);
            try service.upstreams.completed(service, &completion);
            try testing.expectEqual(.none, service.upstreams.operations[self.session].kind);
            try testing.expectEqual(.vacant, service.forward.sessions[self.session].state);
            try testing.expectEqual(null, service.forward.sessions[self.session].transaction);
            try testing.expectEqual(0, service.proctor.ring.sq_ready());
        }

        fn delivered(self: *Fixture, rcode: u4) !void {
            const service = self.service;
            var logs: logging.Capture = .{};
            service.forward.logger = logs.sink();
            defer service.forward.logger = .{};
            try service.deliverForwards();
            try testing.expectEqual(.free, service.forward.transactions[0].state);
            try testing.expectEqual(.response, service.clients[0].phase);
            const header = try wire.Header.decode(service.clients[0].output[2..]);
            try testing.expectEqual(0x1234, header.id);
            try testing.expectEqual(rcode, header.bits & 15);
            try testing.expectEqual(1, service.proctor.ring.sq_ready());
            const tail = service.proctor.ring.sq.sqe_tail;
            const entry = &service.proctor.ring.sq.sqes[(tail -% 1) & service.proctor.ring.sq.mask];
            try testing.expectEqual(linux.IORING_OP.SEND, entry.opcode);
            try testing.expectEqual(32, entry.fd);
            const cache = &service.pipeline.zones[0].cache;
            const positive = cache.positive.entries[0].bytes;
            const denial = cache.denial.entries[0].bytes;
            try service.deliverForwards();
            try testing.expectEqual(tail, service.proctor.ring.sq.sqe_tail);
            try testing.expectEqual(positive, cache.positive.entries[0].bytes);
            try testing.expectEqual(denial, cache.denial.entries[0].bytes);
            try testing.expectEqual(1, logs.count("event=query proto=tcp client=unknown "));
        }
    };

    fn socketPair() ![2]linux.fd_t {
        var descriptors: [2]linux.fd_t = undefined;
        const result = linux.socketpair(
            linux.AF.UNIX,
            linux.SOCK.STREAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC,
            0,
            &descriptors,
        );
        if (linux.errno(result) != .SUCCESS) return error.SocketFailed;
        return descriptors;
    }

    fn negative(value: linux.E) i32 {
        return -@as(i32, @intFromEnum(value));
    }

    // SPEC §§1.1, 1.3: connect success advances once after a non-expired timeout retires.
    test "forward driver pair connect accepts retired timeout results" {
        for ([_]linux.E{ .CANCELED, .ALREADY, .NOENT }) |timeout_result| {
            for (orders) |order| {
                var fixture: Fixture = undefined;
                try fixture.init();
                defer fixture.deinit();
                const service = fixture.service;
                const session = &service.forward.sessions[fixture.session];
                session.state = .connecting;
                const length = session.length;
                try fixture.pair(order, 0, negative(timeout_result));
                try testing.expectEqual(.writing, session.state);
                try testing.expectEqual(0, session.offset);
                try testing.expectEqual(2, service.proctor.ring.sq_ready());
                const entry = &service.proctor.ring.sq.sqes[0];
                try testing.expectEqual(linux.IORING_OP.SEND, entry.opcode);
                try testing.expectEqual(length, entry.len);
                try testing.expectEqual(.waiting, service.clients[0].phase);
                try fixture.empty();
            }
        }
    }

    // SPEC §§1.1, 1.3: both linked owners and explicit cancel barriers precede exactly one rearm.
    test "forward driver pair successful advance waits for every owner" {
        for (orders) |order| {
            var fixture: Fixture = undefined;
            try fixture.init();
            defer fixture.deinit();
            const service = fixture.service;
            const session = &service.forward.sessions[fixture.session];
            const deadline_ns = session.deadline_ns;
            const length = session.length;
            try fixture.pair(order, 1, negative(.CANCELED));
            try testing.expectEqual(.writing, session.state);
            try testing.expectEqual(1, session.offset);
            try testing.expectEqual(deadline_ns, session.deadline_ns);
            try testing.expectEqual(.active, service.forward.transactions[0].state);
            try testing.expectEqual(.waiting, service.clients[0].phase);
            try fixture.empty();
            try testing.expectEqual(2, service.proctor.ring.sq_ready());
            try testing.expectEqual(2, service.proctor.ownership[fixture.slot].generation);
            try testing.expectEqual(2, service.proctor.ownership[fixture.slot + 1].generation);
            const entry = &service.proctor.ring.sq.sqes[0];
            try testing.expectEqual(linux.IORING_OP.SEND, entry.opcode);
            try testing.expectEqual(160 + @as(i32, fixture.session), entry.fd);
            try testing.expectEqual(length - 1, entry.len);
            try testing.expectEqual(@intFromPtr(&session.output[1]), entry.addr);
            try testing.expectEqual(linux.IOSQE_FIXED_FILE | linux.IOSQE_IO_LINK, entry.flags);
            const timeout = &service.proctor.ring.sq.sqes[1];
            try testing.expectEqual(linux.IORING_OP.LINK_TIMEOUT, timeout.opcode);
            try testing.expectEqual(linux.IORING_TIMEOUT_ABS, timeout.rw_flags);
            const operation = &service.upstreams.operations[fixture.session];
            try testing.expectEqual(.pair, operation.kind);
            try testing.expectEqual(null, operation.result);
            try testing.expectEqual(null, operation.timeout_result);
        }
    }

    // SPEC §§1.1, 1.3, 3.7: admission, delivery, and cache publication follow the last barrier.
    test "forward driver pair response publishes once after every owner" {
        for (orders) |order| {
            var fixture: Fixture = undefined;
            try fixture.init();
            defer fixture.deinit();
            const count = try fixture.response();
            try fixture.pair(order, count, negative(.CANCELED));
            const service = fixture.service;
            const transaction = &service.forward.transactions[0];
            try testing.expectEqual(.deliver, transaction.state);
            try testing.expectEqual(.response, std.meta.activeTag(transaction.completion));
            try testing.expectEqual(fixture.session, transaction.completion.response);
            try testing.expectEqual(.idle, service.forward.sessions[fixture.session].state);
            try testing.expectEqual(
                @as(?u16, 0),
                service.forward.sessions[fixture.session].transaction,
            );
            try testing.expectEqual(.none, service.upstreams.operations[fixture.session].kind);
            try testing.expectEqual(0, service.proctor.ring.sq_ready());
            try testing.expectEqual(.waiting, service.clients[0].phase);
            try fixture.empty();
            try fixture.delivered(0);
            try testing.expectEqual(null, service.forward.sessions[fixture.session].transaction);
            try testing.expect(service.pipeline.zones[0].cache.positive.entries[0].bytes != null);
            try testing.expectEqual(null, service.pipeline.zones[0].cache.denial.entries[0].bytes);
        }
    }

    // SPEC §§1.3, 3.6, 3.7: expiry wins against successful I/O and enters transport exhaustion.
    test "forward driver pair timeout and elapsed deadline beat success" {
        const Expiry = enum { linked_success, linked_canceled, elapsed_success };
        for ([_]Expiry{ .linked_success, .linked_canceled, .elapsed_success }) |expiry| {
            for (orders) |order| {
                var fixture: Fixture = undefined;
                try fixture.init();
                defer fixture.deinit();
                const service = fixture.service;
                const count = try fixture.response();
                if (expiry == .elapsed_success)
                    service.forward.sessions[fixture.session].deadline_ns = 0;
                try fixture.pair(
                    order,
                    if (expiry == .linked_canceled) negative(.CANCELED) else count,
                    if (expiry == .elapsed_success) negative(.CANCELED) else negative(.TIME),
                );
                try testing.expectEqual(.active, service.forward.transactions[0].state);
                try fixture.close(.retry);
                try testing.expectEqual(.ready, service.forward.transactions[0].state);
                try testing.expectEqual(1, service.forward.transactions[0].cursor);
                try testing.expectEqual(null, service.forward.select(0, try runtime.nowNs()));
                try testing.expectEqual(.exhausted, service.forward.transactions[0].completion);
                try fixture.delivered(2);
                try testing.expectEqual(
                    null,
                    service.pipeline.zones[0].cache.positive.entries[0].bytes,
                );
                try testing.expect(service.pipeline.zones[0].cache.denial.entries[0].bytes != null);
            }
        }
    }

    // SPEC §§1.3, 3.6, 3.7: local resources retire without retry or terminal cache policy.
    test "forward driver pair resource and transport failures have distinct dispositions" {
        for ([_]linux.E{ .MFILE, .NFILE, .NOBUFS, .NOMEM, .CONNRESET, .PIPE }) |failure| {
            for (orders) |order| {
                var fixture: Fixture = undefined;
                try fixture.init();
                defer fixture.deinit();
                try fixture.pair(order, negative(failure), negative(.CANCELED));
                const service = fixture.service;
                const transaction = &service.forward.transactions[0];
                switch (failure) {
                    .MFILE, .NFILE, .NOBUFS, .NOMEM => {
                        try testing.expectEqual(.deliver, transaction.state);
                        try testing.expectEqual(.local_failure, transaction.completion);
                        try testing.expectEqual(
                            null,
                            service.forward.sessions[fixture.session].transaction,
                        );
                        try fixture.close(.retire);
                        try testing.expectEqual(.deliver, transaction.state);
                        try fixture.delivered(2);
                        try fixture.empty();
                    },
                    else => {
                        try testing.expectEqual(.active, transaction.state);
                        try fixture.close(.retry);
                        try testing.expectEqual(.ready, transaction.state);
                        try testing.expectEqual(
                            null,
                            service.forward.select(0, try runtime.nowNs()),
                        );
                        try testing.expectEqual(.exhausted, transaction.completion);
                        try fixture.delivered(2);
                        try testing.expect(
                            service.pipeline.zones[0].cache.denial.entries[0].bytes != null,
                        );
                    },
                }
                try testing.expectEqual(1, transaction.cursor);
            }
        }
    }

    // SPEC §1.1: stop consumes target results and acknowledgements without any final dispatch.
    test "forward driver pair stopping suppresses every disposition" {
        for ([_]linux.E{ .SUCCESS, .TIME, .NOMEM, .CONNRESET }) |outcome| {
            for (orders) |order| {
                var fixture: Fixture = undefined;
                try fixture.init();
                defer fixture.deinit();
                const count = try fixture.response();
                fixture.service.state = .stopping;
                const before = fixture.snapshot();
                try fixture.pair(
                    order,
                    switch (outcome) {
                        .SUCCESS, .TIME => count,
                        else => negative(outcome),
                    },
                    if (outcome == .TIME) negative(.TIME) else negative(.CANCELED),
                );
                try fixture.preserved(&before);
                try testing.expectEqual(
                    .idle,
                    fixture.service.proctor.ownership[fixture.slot].state,
                );
                try testing.expectEqual(
                    .idle,
                    fixture.service.proctor.ownership[fixture.slot + 1].state,
                );
                try testing.expect(!fixture.service.proctor.pending());
            }
        }
    }
};

// The idle connection metadata is synthetic. Every SEND, RECV, timeout, and CQE is real.
// This listenerless fixture proves neither configured startup nor TCP endpoint association.
const LinuxSubmittedTeardown = struct {
    const linux = std.os.linux;
    const Trace = struct {
        events: [16]Event = undefined,
        count: u32 = 0,
        overflow: u32 = 0,
        const Event = struct {
            kind: enum { allocation, snapshot, release },
            address: usize,
            length: usize,
        };

        fn append(
            self: *Trace,
            kind: @FieldType(Event, "kind"),
            address: usize,
            length: usize,
        ) void {
            if (self.count < self.events.len) {
                self.events[self.count] = .{ .kind = kind, .address = address, .length = length };
                self.count += 1;
            } else self.overflow += 1;
        }

        fn allocator(self: *Trace) std.mem.Allocator {
            return .{ .ptr = self, .vtable = &.{
                .alloc = allocate,
                .resize = std.mem.Allocator.noResize,
                .remap = std.mem.Allocator.noRemap,
                .free = release,
            } };
        }

        fn allocate(
            context: *anyopaque,
            length: usize,
            alignment: std.mem.Alignment,
            caller: usize,
        ) ?[*]u8 {
            const self: *Trace = @ptrCast(@alignCast(context));
            const bytes = testing.allocator.rawAlloc(length, alignment, caller) orelse return null;
            self.append(.allocation, @intFromPtr(bytes), length);
            return bytes;
        }

        fn release(
            context: *anyopaque,
            bytes: []u8,
            alignment: std.mem.Alignment,
            caller: usize,
        ) void {
            const self: *Trace = @ptrCast(@alignCast(context));
            self.append(.release, @intFromPtr(bytes.ptr), bytes.len);
            testing.allocator.rawFree(bytes, alignment, caller);
        }

        fn check(self: *const Trace, runtime_address: usize) !void {
            try testing.expectEqual(0, self.overflow);
            // Runtime, zone metadata, and both cache banks allocate before the snapshot.
            try testing.expectEqual(9, self.count);
            try testing.expectEqual(.snapshot, self.events[4].kind);
            for (self.events[0..4]) |allocation| {
                try testing.expectEqual(.allocation, allocation.kind);
                var matches: u32 = 0;
                for (self.events[5..9]) |released| {
                    try testing.expectEqual(.release, released.kind);
                    if (allocation.address == released.address) {
                        try testing.expectEqual(allocation.length, released.length);
                        matches += 1;
                    }
                }
                try testing.expectEqual(1, matches);
            }
            try testing.expectEqual(runtime_address, self.events[0].address);
            try testing.expectEqual(runtime_address, self.events[8].address);
            try testing.expectEqual(@sizeOf(runtime.Runtime), self.events[8].length);
        }
    };
    const Observation = struct {
        observer: runtime.proctor.TeardownObserver,
        trace: *Trace,
        peers: [2]linux.fd_t = .{ -1, -1 },
        live: Transcript = .{},
        frozen: Transcript = .{},
        calls: u32 = 0,
        cancellation_result: ?usize = null,
        peer_results: [2]isize = .{ -1, -1 },
        peer_errors: [2]system.E = .{ .SUCCESS, .SUCCESS },

        const Transcript = struct {
            marker: ?linux.io_uring_sqe = null,
            submissions: u32 = 0,
            completions: [8]linux.io_uring_cqe = undefined,
            count: u32 = 0,
            overflow: u32 = 0,
        };

        fn init(self: *Observation, trace: *Trace) void {
            self.* = .{
                .observer = .{
                    .context = self,
                    .submitted = submitted,
                    .completed = completed,
                    .observe = snapshot,
                },
                .trace = trace,
            };
        }

        fn submitted(context: *anyopaque, entry: *const linux.io_uring_sqe) void {
            const self: *Observation = @ptrCast(@alignCast(context));
            self.live.marker = entry.*;
            self.live.submissions += 1;
        }

        fn completed(context: *anyopaque, completion: *const linux.io_uring_cqe) void {
            const self: *Observation = @ptrCast(@alignCast(context));
            if (self.live.count < self.live.completions.len) {
                self.live.completions[self.live.count] = completion.*;
                self.live.count += 1;
            } else self.live.overflow += 1;
        }

        fn snapshot(context: *anyopaque) void {
            const self: *Observation = @ptrCast(@alignCast(context));
            self.calls += 1;
            self.cancellation_result = self.observer.cancellation_result;
            // Later real cleanup cannot repair a premature observation in either control.
            self.frozen = self.live;
            for (self.peers, 0..) |descriptor, index| {
                var byte: [1]u8 = undefined;
                const result = system.recv(descriptor, &byte, byte.len, system.MSG.DONTWAIT);
                self.peer_results[index] = result;
                self.peer_errors[index] = std.posix.errno(result);
            }
            self.trace.append(.snapshot, 0, 0);
        }

        fn check(self: *const Observation, tokens: *const [2]u64) !void {
            try testing.expectEqual(1, self.calls);
            // These named assertions distinguish safe observation-order controls.
            var terminal_cancellations: [2]u32 = .{ 0, 0 };
            for (self.frozen.completions[0..self.frozen.count]) |completion| {
                for (tokens, 0..) |token, index| {
                    if (completion.user_data != token) continue;
                    if (completion.res != LinuxPair.negative(.CANCELED)) continue;
                    if (completion.flags & linux.IORING_CQE_F_MORE != 0) continue;
                    terminal_cancellations[index] += 1;
                }
            }
            try testing.expectEqualSlices(u32, &.{ 1, 1 }, &terminal_cancellations);
            try testing.expect(self.cancellation_result != null);
            try testing.expectEqual(.SUCCESS, linux.errno(self.cancellation_result.?));
            try testing.expectEqualSlices(isize, &.{ 0, 0 }, &self.peer_results);
            try testing.expectEqualSlices(system.E, &.{ .SUCCESS, .SUCCESS }, &self.peer_errors);
            try self.checkMarker();
        }

        fn checkMarker(self: *const Observation) !void {
            try testing.expectEqual(0, self.frozen.overflow);
            try testing.expectEqual(3, self.frozen.count);
            try testing.expectEqual(1, self.frozen.submissions);
            try testing.expect(self.frozen.marker != null);
            const marker = self.frozen.marker.?;
            try testing.expectEqual(linux.IORING_OP.NOP, marker.opcode);
            try testing.expectEqual(linux.IOSQE_IO_DRAIN, marker.flags);
            try testing.expectEqual(0, marker.rw_flags);
            try testing.expectEqual(std.math.maxInt(u64), marker.user_data);
            try testing.expect(
                @as(u32, @truncate(marker.user_data)) >= runtime.proctor.operations_max,
            );
            try testing.expectEqual(marker.user_data, self.frozen.completions[2].user_data);
            var matches: u32 = 0;
            for (self.frozen.completions[0..self.frozen.count]) |completion| {
                if (completion.user_data != marker.user_data) continue;
                try testing.expectEqual(0, completion.res);
                try testing.expectEqual(0, completion.flags);
                matches += 1;
            }
            try testing.expectEqual(1, matches);
        }
    };
    const Before = struct {
        send: [2]linux.io_uring_sqe,
        receive: [2]linux.io_uring_sqe,
        tokens: [2]u64,
        owners: [2]runtime.proctor.Ownership,
        queued: u32,
        submitted: u32,
        remaining: u32,
        completions: u32,
        state: @FieldType(runtime.forward.Session, "state"),
        transaction: ?u16,
        transaction_state: @FieldType(runtime.forward.Transaction, "state"),
        operation_kind: @FieldType(
            @TypeOf(@as(runtime.Runtime, undefined).upstreams.operations[0]),
            "kind",
        ),
        operation_result: ?i32,
        timeout_result: ?i32,
        generation: u31,
        peer_generation: u31,
        endpoint: u16,
        peer_endpoint: u16,
        client_phase: @FieldType(runtime.tcp.Client, "phase"),
        cursor: u16,
        buffer_address: usize,
        runtime_address: usize,
        runtime_bytes: usize,
        budget_ns: u64,
        steps: u32,
        expected: [512]u8,
        received: [512]u8,
        expected_length: u32,
        received_length: u32,
    };
    const Fixture = struct {
        service: *runtime.Runtime,
        trace: *Trace,
        observation: *Observation,
        zones: [1]config.Zone,
        settings: config.Config,
        before: Before = undefined,

        fn init(self: *Fixture, trace: *Trace, observation: *Observation) !void {
            self.trace = trace;
            self.observation = observation;
            self.service = try trace.allocator().create(runtime.Runtime);
            errdefer trace.allocator().destroy(self.service);
            const service = self.service;
            service.state = .running;
            service.io = testing.io;
            service.listener_count = 0;
            service.interval = .{ .sec = 1, .nsec = 0 };
            for (&service.listeners) |*listener| {
                listener.udp = null;
                listener.tcp = null;
                listener.message = std.mem.zeroes(linux.msghdr);
            }
            for (&service.clients) |*client| {
                client.state = .vacant;
                client.generation = 0;
            }
            for (&service.responses) |*response| {
                response.state = .free;
                response.generation = 0;
            }
            self.zones = .{.{
                .suffix = ".",
                .upstreams = &.{.{ .address = "127.0.0.1:53", .force_tcp = true }},
                .cache = .{ .capacity = 1 },
                .read_timeout_s = 300,
            }};
            self.settings = .{ .zones = &self.zones };
            try service.forward.init(testing.io, &self.settings);
            service.upstreams.init();
            try service.pipeline.init(trace.allocator(), testing.io, &self.settings);
            errdefer service.pipeline.deinit();
            try service.proctor.init();
            errdefer service.proctor.deinit();
            try service.proctor.ring.register_files_sparse(192);
            try service.proctor.registerClients();
            const upstream_pair = try LinuxPair.socketPair();
            defer _ = linux.close(upstream_pair[0]);
            errdefer _ = linux.close(upstream_pair[1]);
            const client_pair = try LinuxPair.socketPair();
            defer _ = linux.close(client_pair[0]);
            errdefer _ = linux.close(client_pair[1]);
            try service.proctor.ring.register_files_update(160, upstream_pair[0..1]);
            try service.proctor.ring.register_files_update(32, client_pair[0..1]);
            observation.peers = .{ upstream_pair[1], client_pair[1] };
            service.proctor.teardown_observer = &observation.observer;
        }

        fn release(self: *Fixture) void {
            // Unconditional direct teardown retains all production barriers, including in controls.
            self.service.deinit();
            self.trace.allocator().destroy(self.service);
            for (self.observation.peers) |descriptor| _ = linux.close(descriptor);
        }

        fn submit(self: *Fixture) !void {
            const service = self.service;
            const session = &service.forward.sessions[0];
            // Synthetic established-idle state permits reuse without a bind or TCP handshake.
            session.state = .idle;
            session.endpoint = 0;
            session.generation = 1;
            session.deadline_ns = try runtime.nowNs() + 300 * std.time.ns_per_s;
            service.upstreams.operations[0].peer = .{ .endpoint = 0, .generation = 1 };
            service.clients[0].reset();
            service.clients[0].phase = .waiting;
            var input: [512]u8 = undefined;
            const bytes = try query(&input, 0x1234, "teardown.example.");
            _ = service.forward.admit(bytes, 0, &.{
                .index = 0,
                .generation = service.clients[0].generation,
                .transport = .tcp,
            }) orelse return error.AdmissionFailed;
            try service.upstreams.drive(service);
            self.before.send = service.proctor.ring.sq.sqes[0..2].*;
            self.before.expected_length = session.length;
            if (session.length > self.before.expected.len) return error.ShortBuffer;
            @memcpy(self.before.expected[0..session.length], session.output[0..session.length]);
            var steps: u32 = 0;
            for (0..8) |_| {
                if (session.state == .read_prefix) break;
                _ = try service.step();
                steps += 1;
            } else return error.PhaseNotReached;
            self.before.steps = steps;
            var reader: PeerReader = .{ .descriptor = self.observation.peers[0] };
            const frame = try peerFrame(&reader, &self.before.received);
            self.before.received_length = @intCast(frame.len + 2);
            const tail = service.proctor.ring.sq.sqe_tail;
            for (&self.before.receive, 0..) |*entry, index| {
                entry.* = service.proctor.ring.sq.sqes[
                    (tail -% 2 +% @as(u32, @intCast(index))) & service.proctor.ring.sq.mask
                ];
            }
            self.before.queued = service.proctor.ring.sq_ready();
            self.before.submitted = try service.proctor.ring.submit();
            self.capture();
        }

        fn capture(self: *Fixture) void {
            const service = self.service;
            const session = &service.forward.sessions[0];
            const operation = &service.upstreams.operations[0];
            const before = &self.before;
            before.remaining = service.proctor.ring.sq_ready();
            before.completions = service.proctor.ring.cq_ready();
            before.owners = service.proctor.ownership[225..227].*;
            before.tokens = .{ before.owners[0].token(225), before.owners[1].token(226) };
            before.state = session.state;
            before.transaction = session.transaction;
            before.transaction_state = service.forward.transactions[0].state;
            before.cursor = service.forward.transactions[0].cursor;
            before.operation_kind = operation.kind;
            before.operation_result = operation.result;
            before.timeout_result = operation.timeout_result;
            before.generation = session.generation;
            before.peer_generation = operation.peer.generation;
            before.endpoint = session.endpoint;
            before.peer_endpoint = operation.peer.endpoint;
            before.client_phase = service.clients[0].phase;
            before.buffer_address = @intFromPtr(&session.input[0]);
            before.runtime_address = @intFromPtr(service);
            before.runtime_bytes = @sizeOf(runtime.Runtime);
            before.budget_ns = session.deadline_ns -| (runtime.nowNs() catch session.deadline_ns);
        }
    };

    fn checkBefore(before: *const Before) !void {
        try testing.expectEqual(linux.IORING_OP.SEND, before.send[0].opcode);
        try testing.expectEqual(160, before.send[0].fd);
        try testing.expectEqual(linux.IOSQE_FIXED_FILE | linux.IOSQE_IO_LINK, before.send[0].flags);
        try testing.expectEqual(linux.IORING_OP.LINK_TIMEOUT, before.send[1].opcode);
        try testing.expectEqual(linux.IORING_TIMEOUT_ABS, before.send[1].rw_flags);
        try testing.expectEqual(before.expected_length, before.send[0].len);
        try testing.expectEqual(2, before.steps);
        try testing.expectEqual(before.expected_length, before.received_length);
        try testing.expectEqualSlices(
            u8,
            before.expected[0..before.expected_length],
            before.received[0..before.received_length],
        );
        try testing.expectEqual(linux.IORING_OP.RECV, before.receive[0].opcode);
        try testing.expectEqual(160, before.receive[0].fd);
        try testing.expectEqual(
            linux.IOSQE_FIXED_FILE | linux.IOSQE_IO_LINK,
            before.receive[0].flags,
        );
        try testing.expectEqual(2, before.receive[0].len);
        try testing.expectEqual(before.buffer_address, before.receive[0].addr);
        try testing.expect(before.buffer_address >= before.runtime_address);
        try testing.expect(
            before.buffer_address + 2 <= before.runtime_address + before.runtime_bytes,
        );
        try testing.expectEqual(linux.IORING_OP.LINK_TIMEOUT, before.receive[1].opcode);
        try testing.expectEqual(linux.IORING_TIMEOUT_ABS, before.receive[1].rw_flags);
        for (&before.receive, &before.tokens, &before.owners) |*entry, token, *owner| {
            try testing.expectEqual(token, entry.user_data);
            try testing.expectEqual(.active, owner.state);
            try testing.expectEqual(2, owner.generation);
        }
        try testing.expectEqual(2, before.queued);
        try testing.expectEqual(2, before.submitted);
        try testing.expectEqual(0, before.remaining);
        try testing.expectEqual(0, before.completions);
        try testing.expectEqual(.read_prefix, before.state);
        try testing.expectEqual(@as(?u16, 0), before.transaction);
        try testing.expectEqual(.active, before.transaction_state);
        try testing.expectEqual(1, before.cursor);
        try testing.expectEqual(.pair, before.operation_kind);
        try testing.expectEqual(null, before.operation_result);
        try testing.expectEqual(null, before.timeout_result);
        try testing.expectEqual(1, before.generation);
        try testing.expectEqual(before.generation, before.peer_generation);
        try testing.expectEqual(0, before.endpoint);
        try testing.expectEqual(before.endpoint, before.peer_endpoint);
        try testing.expectEqual(.waiting, before.client_phase);
        try testing.expect(before.budget_ns > 170 * std.time.ns_per_s);
    }

    fn printTrace(
        before: *const Before,
        observation: *const Observation,
        trace: *const Trace,
    ) void {
        std.debug.print(
            "SUBMITTED_TEARDOWN tokens={any} fixed_file={d} buffer=0x{x} runtime=0x{x}" ++
                " queued={d} submitted={d} remaining={d} cq_before={d} budget_ns={d}\n",
            .{
                before.tokens,          before.receive[0].fd, before.buffer_address,
                before.runtime_address, before.queued,        before.submitted,
                before.remaining,       before.completions,   before.budget_ns,
            },
        );
        std.debug.print(
            "TEARDOWN_SNAPSHOT calls={d} cancel={any} syscall={any}" ++
                " retired={d} peers={any} errors={any}\n",
            .{
                observation.calls,                        observation.cancellation_result,
                observation.observer.cancellation_result, observation.frozen.count,
                observation.peer_results,                 observation.peer_errors,
            },
        );
        if (observation.frozen.marker) |marker|
            std.debug.print("TEARDOWN_MARKER opcode={s} flags={d} opcode_flags={d} token={d}\n", .{
                @tagName(marker.opcode), marker.flags, marker.rw_flags, marker.user_data,
            });
        for (observation.frozen.completions[0..observation.frozen.count]) |completion|
            std.debug.print("TEARDOWN_CQE token={d} result={d} flags={d}\n", .{
                completion.user_data, completion.res, completion.flags,
            });
        for (trace.events[0..trace.count], 0..) |event, index|
            std.debug.print("TEARDOWN_MEMORY index={d} kind={s} address=0x{x} length={d}\n", .{
                index, @tagName(event.kind), event.address, event.length,
            });
    }

    // SPEC §§1.1, 1.3: direct teardown cancels submitted upstream work before storage release.
    test "forward submitted receive direct Runtime teardown release barriers" {
        var trace: Trace = .{};
        var observation: Observation = undefined;
        observation.init(&trace);
        var fixture: Fixture = undefined;
        try fixture.init(&trace, &observation);
        const submitted = fixture.submit();
        // No stop or pre-drain occurs. All assertions use external values after destruction.
        fixture.release();
        try submitted;
        printTrace(&fixture.before, &observation, &trace);
        try checkBefore(&fixture.before);
        try observation.check(&fixture.before.tokens);
        try trace.check(fixture.before.runtime_address);
    }
};

const DatagramPeer = struct {
    descriptor: system.fd_t,
    source: runtime.address.Address = undefined,

    fn init(self: *DatagramPeer, harness: *Harness) !void {
        self.descriptor = try harness.upstream_address.bind(system.SOCK.DGRAM);
    }

    fn request(self: *DatagramPeer, harness: *Harness, output: []u8) ![]const u8 {
        for (0..256) |_| {
            self.source.length = @sizeOf(@TypeOf(self.source.storage));
            const count = system.recvfrom(
                self.descriptor,
                output.ptr,
                output.len,
                0,
                @ptrCast(&self.source.storage),
                &self.source.length,
            );
            if (count >= 0) return output[0..@intCast(count)];
            if (std.posix.errno(count) != .AGAIN) return error.ReceiveFailed;
            try testing.expect(try harness.service.step());
        }
        return error.RequestNotReceived;
    }

    fn respond(self: *DatagramPeer, bytes: []const u8) !void {
        const count = system.sendto(
            self.descriptor,
            bytes.ptr,
            bytes.len,
            0,
            @ptrCast(&self.source.storage),
            self.source.length,
        );
        try testing.expectEqual(@as(isize, @intCast(bytes.len)), count);
    }
};

// SPEC §§3.6, 3.7, 4: a UDP answer and cache hit never imply an unused TLS exchange.
test "forward UDP native answer with unused TLS fallback and cache hit logging" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var peer: DatagramPeer = undefined;
    try peer.init(&harness);
    defer _ = system.close(peer.descriptor);
    harness.upstreams[0].force_tcp = false;
    harness.upstreams[1].tls = .{ .server_name = "dns.example" };
    harness.zones[0].upstreams = &harness.upstreams;
    harness.zones[0].cache = .{ .capacity = 1 };
    try harness.start();
    var logs: logging.Capture = .{};
    harness.service.forward.logger = logs.sink();
    try testing.expectEqual(.supported, harness.service.forward.support[0]);
    const client = try harness.client(system.SOCK.DGRAM);
    defer _ = system.close(client);
    var input: [512]u8 = undefined;
    var upstream: [512]u8 = undefined;
    var response: [512]u8 = undefined;
    var output: [512]u8 = undefined;
    try send(client, try query(&input, 42, "udp.example."));
    const request = try peer.request(&harness, &upstream);
    const framed = try answer(&response, request, 0, 1);
    try peer.respond(framed[2..]);
    const length = try harness.receive(client, &output);
    const header = try wire.Header.decode(output[0..length]);
    try testing.expectEqual(42, header.id);
    try testing.expectEqual(0, header.bits & 15);
    try testing.expectEqual(1, header.counts[1]);
    try testing.expect(harness.service.pipeline.zones[0].cache.positive.entries[0].bytes != null);
    try send(client, try query(&input, 43, "udp.example."));
    const cached = try harness.receive(client, &output);
    try testing.expectEqual(43, (try wire.Header.decode(output[0..cached])).id);
    try testing.expectEqual(system.E.AGAIN, std.posix.errno(system.recv(
        peer.descriptor,
        &upstream,
        upstream.len,
        0,
    )));
    try testing.expectEqual(2, logs.count("event=query"));
    try testing.expectEqual(1, logs.count("src=cache"));
    try testing.expectEqual(1, logs.count("upstream="));
    try testing.expectEqual(0, logs.count("tls_name="));
    try testing.expectEqual(0, logs.count("upstream_proto=dot"));
    try logs.client(client, .udp);
    try harness.stop();
}

// SPEC §§3.6, 3.9: a connected UDP socket rejects other sources and ignores invalid replies.
test "forward UDP native ignores empty malformed wrong ID and wrong source replies" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var peer: DatagramPeer = undefined;
    try peer.init(&harness);
    defer _ = system.close(peer.descriptor);
    harness.upstreams[0].force_tcp = false;
    try harness.start();
    const client = try harness.client(system.SOCK.DGRAM);
    defer _ = system.close(client);
    var input: [512]u8 = undefined;
    var upstream: [512]u8 = undefined;
    var response: [512]u8 = undefined;
    var output: [512]u8 = undefined;
    try send(client, try query(&input, 51, "ignore.example."));
    const request = try peer.request(&harness, &upstream);
    try peer.respond(&.{});
    try peer.respond(&.{ 0, 1, 2 });
    const wrong = try answer(&response, request, 0, 1);
    response[2] ^= 1;
    try peer.respond(wrong[2..]);
    const stranger = system.socket(system.AF.INET, system.SOCK.DGRAM, 0);
    try testing.expect(stranger >= 0);
    defer _ = system.close(stranger);
    const forged = try answer(&response, request, 0, 1);
    try testing.expectEqual(@as(isize, @intCast(forged.len - 2)), system.sendto(
        stranger,
        forged[2..].ptr,
        forged.len - 2,
        0,
        @ptrCast(&peer.source.storage),
        peer.source.length,
    ));
    const valid = try answer(&response, request, 0, 2);
    try peer.respond(valid[2..]);
    const length = try harness.receive(client, &output);
    const header = try wire.Header.decode(output[0..length]);
    try testing.expectEqual(51, header.id);
    try testing.expectEqual(2, header.counts[1]);
    try harness.stop();
}

// SPEC §§3.6, 3.9: TC returns to the client. Its TCP retry uses TCP, not the idle UDP socket.
test "forward UDP native truncation and client TCP retry" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var peer: DatagramPeer = undefined;
    try peer.init(&harness);
    defer _ = system.close(peer.descriptor);
    harness.upstreams[0].force_tcp = false;
    harness.zones[0].cache = .{ .capacity = 1 };
    try harness.start();
    const client = try harness.client(system.SOCK.DGRAM);
    defer _ = system.close(client);
    var input: [512]u8 = undefined;
    var upstream: [512]u8 = undefined;
    var response: [512]u8 = undefined;
    var output: [512]u8 = undefined;
    const bytes = try query(input[2..], 52, "truncated.example.");
    try send(client, bytes);
    const request = try peer.request(&harness, &upstream);
    const truncated = try answer(&response, request, 0, 1);
    response[4] |= 2;
    try peer.respond(truncated[2..]);
    const length = try harness.receive(client, &output);
    try testing.expect((try wire.Header.decode(output[0..length])).has(.truncated));
    try emptyCache(&harness);
    const stream = try harness.client(system.SOCK.STREAM);
    defer _ = system.close(stream);
    try wire.framePrefix(&input, bytes.len);
    try send(stream, input[0 .. bytes.len + 2]);
    const retry = try harness.request(&upstream);
    try testing.expectEqual(.tcp, harness.service.forward.sessions[retry.session].transport);
    try send(harness.peer.?, try answer(&response, retry.bytes, 0, 2));
    const full = try harness.frame(stream, &output);
    const header = try wire.Header.decode(full);
    try testing.expect(!header.has(.truncated));
    try testing.expectEqual(2, header.counts[1]);
    try harness.stop();
}

// SPEC §3.6, §4: a silent UDP primary times out before the next configured TCP member answers.
test "forward UDP native timeout advances to TCP fallback logging" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var peer: DatagramPeer = undefined;
    try peer.init(&harness);
    defer _ = system.close(peer.descriptor);
    var fallback_address: runtime.address.Address = undefined;
    var fallback_text: [64]u8 = undefined;
    const fallback = try endpoint(&fallback_address, &fallback_text);
    _ = system.close(harness.listener.?);
    harness.listener = fallback;
    harness.upstreams[1].address = std.mem.sliceTo(&fallback_text, 0);
    harness.upstreams[0].force_tcp = false;
    harness.zones[0].upstreams = &harness.upstreams;
    harness.zones[0].read_timeout_s = 0.05;
    try harness.start();
    var logs: logging.Capture = .{};
    harness.service.forward.logger = logs.sink();
    const client = try harness.client(system.SOCK.DGRAM);
    defer _ = system.close(client);
    var input: [512]u8 = undefined;
    var upstream: [512]u8 = undefined;
    var response: [512]u8 = undefined;
    var output: [512]u8 = undefined;
    try send(client, try query(&input, 53, "timeout.example."));
    _ = try peer.request(&harness, &upstream);
    // The UDP send CQE must retire before the TCP-only helper waits for another write phase.
    _ = try harness.phase(.read_datagram);
    const retry = try harness.request(&upstream);
    try testing.expectEqual(1, harness.service.forward.sessions[retry.session].endpoint);
    try send(harness.peer.?, try answer(&response, retry.bytes, 0, 1));
    const length = try harness.receive(client, &output);
    try testing.expectEqual(1, (try wire.Header.decode(output[0..length])).counts[1]);
    try testing.expectEqual(1, logs.count("event=query"));
    try testing.expectEqual(1, logs.count("event=upstream_failure"));
    try logs.contains("upstream_proto=udp reason=\"timeout\"");
    try logs.contains("upstream_proto=tcp");
    var selected: [128]u8 = undefined;
    try logs.contains(try std.fmt.bufPrint(
        &selected,
        "src=forward upstream={s} upstream_proto=tcp",
        .{harness.upstreams[1].address},
    ));
    try harness.stop();
}

// SPEC §§3.6, 3.7, 5.1: unresolved hostnames cause local failure, not transport exhaustion.
test "forward UDP native timeout distinguishes exhaustion from unsupported hostname" {
    for ([_]enum { exhausted, hostname }{ .exhausted, .hostname }) |ending| {
        var harness: Harness = undefined;
        try harness.init();
        defer harness.deinit();
        var peer: DatagramPeer = undefined;
        try peer.init(&harness);
        defer _ = system.close(peer.descriptor);
        harness.upstreams[0].force_tcp = false;
        if (ending == .hostname) {
            harness.upstreams[1].address = "dns.example:853";
            harness.zones[0].upstreams = &harness.upstreams;
        }
        harness.zones[0].read_timeout_s = 0.01;
        harness.zones[0].cache = .{ .capacity = 1 };
        try harness.start();
        const client = try harness.client(system.SOCK.DGRAM);
        defer _ = system.close(client);
        var input: [512]u8 = undefined;
        var upstream: [512]u8 = undefined;
        var output: [512]u8 = undefined;
        try send(client, try query(&input, 54, "failure.example."));
        _ = try peer.request(&harness, &upstream);
        const length = try harness.receive(client, &output);
        try testing.expectEqual(2, (try wire.Header.decode(output[0..length])).bits & 15);
        const denial = &harness.service.pipeline.zones[0].cache.denial.entries[0];
        switch (ending) {
            .exhausted => {
                try testing.expect(denial.bytes != null);
                try testing.expectEqual(5, denial.lifetime_s);
            },
            .hostname => try testing.expectEqual(null, denial.bytes),
        }
        try harness.stop();
    }
}

// SPEC §§3.6, 3.9: datagrams do not accumulate partial stream writes or DNS length prefixes.
test "forward UDP datagram boundaries and partial send rejection" {
    const forward = try testing.allocator.create(runtime.forward.Forward);
    defer testing.allocator.destroy(forward);
    const session = &forward.sessions[0];
    session.transport = .udp;
    session.startRead();
    try testing.expectEqual(.frame, session.received(0));
    try testing.expectEqual(2, session.length);
    session.startRead();
    try testing.expectEqual(.frame, session.received(12));
    try testing.expectEqual(14, session.length);
    session.startRead();
    try testing.expectEqual(.failed, session.received(65536));
    session.state = .writing;
    session.offset = 2;
    session.length = 14;
    try testing.expectEqual(.failed, forward.sent(0, 1, 0));
    try testing.expectEqual(2, session.offset);
}

const tls = runtime.forward.tls.engine;
const DotPeer = struct {
    descriptor: ?system.fd_t = null,
    handshake: tls.ServerHandshake,
    signer: tls.signature.PrivateKey,
    chain: [1][]const u8 = .{@embedFile("fixtures/dot-ca.der")},
    records: tls.RecordBuffer,
    storage: [33290]u8,
    output: [16645]u8,
    flight: tls.ServerHandshake.FlightBuffer,
    request: [65537]u8,
    request_length: u32 = 0,
    requests: u32 = 0,
    connections: u32 = 0,

    fn init(self: *DotPeer) !void {
        self.descriptor = null;
        self.requests = 0;
        self.connections = 0;
        self.chain = .{@embedFile("fixtures/dot-ca.der")};
        self.signer = try .fromPem(.ecdsa_secp256r1_sha256, @embedFile("fixtures/dot-key.pem"));
        self.reset();
    }

    fn reset(self: *DotPeer) void {
        self.handshake = .init(.{
            .keypairs = .initWithP256(.generate(), .generate()),
            .random = .zero,
        });
        self.handshake.setCredentials(&self.chain, self.signer.signer());
        self.records = .init(&self.storage);
        self.request_length = 0;
        self.flight = .empty;
    }

    fn deinit(self: *DotPeer) void {
        if (self.descriptor) |descriptor| _ = system.close(descriptor);
        self.handshake.deinit();
        self.signer.deinit();
        self.* = undefined;
    }

    fn step(self: *DotPeer, listener: system.fd_t) !void {
        if (self.descriptor == null) {
            const descriptor = system.accept(listener, null, null);
            if (descriptor < 0) {
                if (std.posix.errno(descriptor) == .AGAIN) return;
                return error.AcceptFailed;
            }
            self.descriptor = descriptor;
            self.connections += 1;
            try nonblocking(descriptor);
        }
        const buffer = self.records.writable();
        const count = system.recv(self.descriptor.?, buffer.ptr, buffer.len, 0);
        if (count < 0) {
            if (std.posix.errno(count) == .AGAIN) return;
            return error.ReceiveFailed;
        }
        if (count == 0) {
            _ = system.close(self.descriptor.?);
            self.descriptor = null;
            self.handshake.deinit();
            self.reset();
            return;
        }
        self.records.advance(@intCast(count));
        for (0..4096) |_| {
            const record = try self.records.next() orelse return;
            switch (try self.handshake.handleRecord(record, &self.output)) {
                .write => |bytes| {
                    try self.write(bytes);
                    if (try self.handshake.sendServerFlightBuffered(&self.flight)) |flight|
                        try self.write(flight);
                },
                .application_data => |bytes| try self.respond(bytes),
                .key_update => |update| if (update.response) |bytes| try self.write(bytes),
                .none => {},
                else => return error.UnexpectedTlsEvent,
            }
        }
        return error.TooManyRecords;
    }

    fn write(self: *DotPeer, bytes: []const u8) !void {
        // Separate socket writes also split the TLS header, without a timing dependency.
        const first = @min(3, bytes.len);
        try send(self.descriptor.?, bytes[0..first]);
        try send(self.descriptor.?, bytes[first..]);
        self.handshake.completeWrite();
    }

    fn respond(self: *DotPeer, bytes: []const u8) !void {
        if (bytes.len > self.request.len - self.request_length) return error.ShortBuffer;
        @memcpy(self.request[self.request_length..][0..bytes.len], bytes);
        self.request_length += @intCast(bytes.len);
        if (self.request_length < 2) return;
        const length = 2 + @as(u32, wire.integer(u16, self.request[0..2]));
        if (self.request_length < length) return;
        try testing.expectEqual(length, self.request_length);
        var response: [512]u8 = undefined;
        const framed = try answer(&response, self.request[2..length], 0, 1);
        // KeyUpdate requires a response before the next request can use the new keys.
        try self.write(try self.handshake.sendKeyUpdate(&self.output, .update_requested));
        try self.write(try self.handshake.sendApplicationData(framed[0..1], &self.output));
        try self.write(try self.handshake.sendApplicationData(framed[1..7], &self.output));
        try self.write(try self.handshake.sendApplicationData(framed[7..], &self.output));
        self.requests += 1;
        self.request_length = 0;
    }
};

fn dotTrust(harness: *Harness) !void {
    const trust = &harness.service.forward.trust;
    var allocator: std.heap.FixedBufferAllocator = .init(&trust.storage);
    trust.bundle = .empty;
    try trust.bundle.bytes.appendSlice(allocator.allocator(), @embedFile("fixtures/dot-ca.der"));
    try trust.bundle.parseCert(
        allocator.allocator(),
        0,
        std.Io.Timestamp.now(testing.io, .real).toSeconds(),
    );
}

fn dotReceive(harness: *Harness, peer: *DotPeer, client: system.fd_t, output: []u8) !usize {
    for (0..1024) |_| {
        try peer.step(harness.listener.?);
        const count = system.recv(client, output.ptr, output.len, 0);
        if (count >= 0) return @intCast(count);
        if (std.posix.errno(count) != .AGAIN) return error.ReceiveFailed;
        try testing.expect(try harness.service.step());
    }
    return error.ResponseNotReceived;
}

// SPEC §§3.6, 3.9, §4: TLS retains authentication across transports and fragmented records.
test "forward TLS native encrypted exchange reuse and key update logging" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    harness.upstreams[0].tls = .{ .server_name = "dns.example" };
    harness.zones[0].cache = .{ .capacity = 2 };
    try harness.start();
    var logs: logging.Capture = .{};
    harness.service.forward.logger = logs.sink();
    try dotTrust(&harness);
    var peer: DotPeer = undefined;
    try peer.init();
    defer peer.deinit();
    var input: [512]u8 = undefined;
    var output: [512]u8 = undefined;
    var generation: u31 = 0;
    for ([_]u32{ system.SOCK.DGRAM, system.SOCK.STREAM }) |kind| {
        const client = try harness.client(kind);
        defer _ = system.close(client);
        const request = try query(input[2..], 61, if (kind == system.SOCK.DGRAM)
            "encrypted.example."
        else
            "stream.example.");
        try wire.framePrefix(&input, request.len);
        try send(client, if (kind == system.SOCK.DGRAM) request else input[0 .. request.len + 2]);
        const length = try dotReceive(&harness, &peer, client, &output);
        const bytes = if (kind == system.SOCK.DGRAM) output[0..length] else output[2..length];
        try testing.expectEqual(1, (try wire.Header.decode(bytes)).counts[1]);
        try testing.expectEqual(61, (try wire.Header.decode(bytes)).id);
        try logs.client(client, if (kind == system.SOCK.DGRAM) .udp else .tcp);
        for (&harness.service.forward.sessions) |*session| {
            if (session.state != .idle) continue;
            try testing.expectEqual(.tls, session.transport);
            if (generation != 0) try testing.expectEqual(generation, session.generation);
            generation = session.generation;
        }
    }
    const cached_client = try harness.client(system.SOCK.DGRAM);
    defer _ = system.close(cached_client);
    try send(cached_client, try query(&input, 65, "encrypted.example."));
    const cached_length = try harness.receive(cached_client, &output);
    try testing.expectEqual(65, (try wire.Header.decode(output[0..cached_length])).id);
    try logs.client(cached_client, .udp);
    try testing.expectEqual(1, logs.count("src=cache"));
    try testing.expectEqual(2, peer.requests);
    try testing.expectEqual(1, peer.connections);
    try testing.expectEqual(3, logs.count("event=query"));
    try testing.expectEqual(2, logs.count("upstream_proto=dot"));
    try testing.expectEqual(2, logs.count("proto=udp client=127.0.0.1:"));
    try testing.expectEqual(1, logs.count("proto=tcp client=127.0.0.1:"));
    try logs.contains("tls_name=\"dns.example\"");
    try harness.stop();
}

// SPEC §3.6: CA and hostname failures are transport failures, never plaintext on the TLS member.
test "forward TLS native rejects wrong hostname and untrusted CA" {
    for ([_]enum { hostname, authority }{ .hostname, .authority }) |failure| {
        var harness: Harness = undefined;
        try harness.init();
        defer harness.deinit();
        harness.upstreams[0].tls = .{ .server_name = if (failure == .hostname)
            "wrong.example"
        else
            "dns.example" };
        harness.zones[0].cache = .{ .capacity = 1 };
        try harness.start();
        if (failure == .hostname) try dotTrust(&harness);
        var peer: DotPeer = undefined;
        try peer.init();
        defer peer.deinit();
        const client = try harness.client(system.SOCK.DGRAM);
        defer _ = system.close(client);
        var input: [512]u8 = undefined;
        var output: [512]u8 = undefined;
        try send(client, try query(&input, 62, "untrusted.example."));
        const length = try dotReceive(&harness, &peer, client, &output);
        try testing.expectEqual(2, (try wire.Header.decode(output[0..length])).bits & 15);
        try testing.expectEqual(0, peer.requests);
        try testing.expectEqual(1, peer.connections);
        const denial = &harness.service.pipeline.zones[0].cache.denial.entries[0];
        try testing.expectEqual(5, denial.lifetime_s);
        try harness.stop();
    }
}

// SPEC §3.6, §4: a failed TLS handshake advances the sequence to another verified TLS member.
test "forward TLS native authentication failure advances configured sequence logging" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    harness.upstreams[0].tls = .{ .server_name = "wrong.example" };
    harness.upstreams[1].tls = .{ .server_name = "dns.example" };
    harness.zones[0].upstreams = &harness.upstreams;
    try harness.start();
    var logs: logging.Capture = .{};
    harness.service.forward.logger = logs.sink();
    try dotTrust(&harness);
    var peer: DotPeer = undefined;
    try peer.init();
    defer peer.deinit();
    const client = try harness.client(system.SOCK.DGRAM);
    defer _ = system.close(client);
    var input: [512]u8 = undefined;
    var output: [512]u8 = undefined;
    try send(client, try query(&input, 63, "fallback.example."));
    const length = try dotReceive(&harness, &peer, client, &output);
    try testing.expectEqual(1, (try wire.Header.decode(output[0..length])).counts[1]);
    try testing.expectEqual(1, peer.requests);
    try testing.expectEqual(2, peer.connections);
    try testing.expectEqual(1, logs.count("event=query"));
    try testing.expectEqual(1, logs.count("event=upstream_failure"));
    try logs.contains("tls_name=\"wrong.example\" reason=\"CertificateHostMismatch\"");
    try logs.contains("src=forward");
    try logs.contains("tls_name=\"dns.example\"");
    try testing.expect(std.mem.indexOf(u8, logs.bytes(), "event=upstream_failure").? <
        std.mem.indexOf(u8, logs.bytes(), "event=query").?);
    try harness.stop();
}

// SPEC §3.6: TLS takes precedence over both client transport and force_tcp.
test "forward TLS selection cannot downgrade TCP clients" {
    const forward = try testing.allocator.create(runtime.forward.Forward);
    defer testing.allocator.destroy(forward);
    var zones = [_]config.Zone{.{ .suffix = ".", .cache = null, .upstreams = &.{.{
        .address = "127.0.0.1:853",
        .force_tcp = true,
        .tls = .{ .server_name = "dns.example" },
    }} }};
    const settings: config.Config = .{ .zones = &zones };
    try forward.init(testing.io, &settings);
    defer forward.deinit();
    var input: [512]u8 = undefined;
    const bytes = try query(&input, 64, "selection.example.");
    for ([_]runtime.pipeline.Transport{ .{ .udp = .ipv4 }, .tcp }) |transport| {
        const transaction = forward.admit(bytes, 0, &.{
            .index = 0,
            .generation = 1,
            .transport = transport,
        }).?;
        const selection = forward.select(transaction, 0).?;
        try testing.expectEqual(.tls, forward.sessions[selection.session].transport);
    }
}

// RFC 8446 §4.4: partial socket writes cannot acknowledge pending handshake output.
test "forward TLS partial write retains engine acknowledgement and rejects overrun" {
    const connection = try testing.allocator.create(runtime.forward.tls.Connection);
    defer testing.allocator.destroy(connection);
    connection.handshake = null;
    const trust = try testing.allocator.create(runtime.forward.tls.Trust);
    defer testing.allocator.destroy(trust);
    trust.bundle = .empty;
    try connection.init(testing.io, "dns.example", trust);
    defer connection.deinit();
    connection.begin(12);
    try testing.expectEqual(.write, try connection.next(&.{}));
    const original = connection.pending().len;
    try connection.sent(1);
    try testing.expectEqual(original - 1, connection.pending().len);
    var output: [16645]u8 = undefined;
    try testing.expectError(error.PendingWrite, connection.handshake.?.handleRecord(&.{}, &output));
    try testing.expectError(error.TransportFailure, connection.sent(@intCast(original)));
    try connection.sent(@intCast(original - 1));
    try testing.expectEqual(.read, try connection.next(&.{}));
    try testing.expectError(error.TransportFailure, connection.received(0));
    try testing.expectError(error.TransportFailure, connection.received(33291));
}

// SPEC §§3.9, 4: fragmented and coalesced local TCP frames publish once per response.
test "logging native local fragmented and coalesced TCP and sink failure" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    try harness.start();
    var logs: logging.Capture = .{};
    harness.service.forward.logger = logs.sink();
    const client = try harness.client(system.SOCK.STREAM);
    defer _ = system.close(client);
    var input: [512]u8 = undefined;
    var output: [512]u8 = undefined;
    const bytes = try query(input[2..], 70, "localhost.");
    try wire.framePrefix(&input, bytes.len);
    try send(client, input[0..1]);
    // Consume actual partial-prefix progress before the remainder reaches the socket.
    for (0..16) |_| {
        if (harness.service.clients[0].offset == 1) break;
        try testing.expect(try harness.service.step());
    }
    try testing.expectEqual(1, harness.service.clients[0].offset);
    try testing.expectEqual(0, logs.count("event=query"));
    try send(client, input[1 .. bytes.len + 2]);
    _ = try harness.frame(client, &output);
    var coalesced: [1024]u8 = undefined;
    const frame_length = bytes.len + 2;
    @memcpy(coalesced[0..frame_length], input[0..frame_length]);
    @memcpy(coalesced[frame_length..][0..frame_length], input[0..frame_length]);
    try send(client, coalesced[0 .. frame_length * 2]);
    _ = try harness.frame(client, &output);
    _ = try harness.frame(client, &output);
    try testing.expectEqual(3, logs.count("event=query"));
    try testing.expectEqual(3, logs.count("src=rfc6761"));
    try testing.expectEqual(0, logs.count("upstream="));
    try logs.client(client, .tcp);
    logs.mode = .fail;
    try send(client, input[0..frame_length]);
    const received = try harness.frame(client, &output);
    try testing.expectEqual(1, (try wire.Header.decode(received)).counts[1]);
    try testing.expectEqual(4, logs.attempts);
    try harness.stop();
}

// SPEC §§1.1, 1.2, 4: coalesced accepts retain distinct peers without a shared sockaddr.
test "logging native concurrent TCP accepts retain distinct peers" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    try harness.start();
    var logs: logging.Capture = .{};
    harness.service.forward.logger = logs.sink();
    const first = try harness.client(system.SOCK.STREAM);
    defer _ = system.close(first);
    const other = try harness.client(system.SOCK.STREAM);
    defer _ = system.close(other);
    var input: [512]u8 = undefined;
    var output: [512]u8 = undefined;
    const bytes = try query(input[2..], 71, "localhost.");
    try wire.framePrefix(&input, bytes.len);
    try send(first, input[0 .. bytes.len + 2]);
    try send(other, input[0 .. bytes.len + 2]);
    _ = try harness.frame(first, &output);
    _ = try harness.frame(other, &output);
    try logs.client(first, .tcp);
    try logs.client(other, .tcp);
    try testing.expectEqual(2, logs.count("event=query"));
    try testing.expectEqual(0, logs.count("client=unknown"));
    try harness.stop();
}

// SPEC §§1.3, 3.2, 3.7, 3.9, 4: eight clients retain identities through a full cache (#1).
test "cache stress native full cache mixed concurrent clients and upstream reuse" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    harness.zones[0].cache = .{ .capacity = 128, .min_ttl_s = 60 };
    harness.zones[0].read_timeout_s = 0.2;
    try harness.start();
    var logs: logging.Capture = .{};
    harness.service.forward.logger = logs.sink();
    var clients: [8]?system.fd_t = @splat(null);
    defer for (clients) |client| {
        if (client) |descriptor| _ = system.close(descriptor);
    };
    for (&clients, 0..) |*client, index|
        client.* = try harness.client(if (index < 4) system.SOCK.DGRAM else system.SOCK.STREAM);
    const packet = try testing.allocator.create(wire.Packet);
    defer testing.allocator.destroy(packet);
    const deadline_ns = try runtime.nowNs() + 10 * std.time.ns_per_s;
    try fillStressCache(&harness, clients[0].?, &logs, packet, deadline_ns);
    const allocations = harness.allocator.alloc_index;
    harness.allocator.fail_index = allocations;
    var input: [512]u8 = undefined;
    var output: [512]u8 = undefined;
    for (0..64) |round| {
        logs = .{};
        for (clients, 0..) |client, index| {
            try testing.expect(try runtime.nowNs() < deadline_ns);
            const key: u16 = @intCast((round * 17 + index * 31) % 128);
            const id: u16 = @intCast(1000 + round * 8 + index);
            const bytes = try stressQuery(input[2..], id, key);
            try wire.framePrefix(&input, bytes.len);
            try send(client.?, if (index < 4) bytes else input[0 .. bytes.len + 2]);
        }
        for (clients, 0..) |client, index| {
            const bytes = if (index < 4)
                output[0..try harness.receive(client.?, &output)]
            else
                try harness.frame(client.?, &output);
            try stressAnswer(
                packet,
                bytes,
                @intCast(1000 + round * 8 + index),
                @intCast((round * 17 + index * 31) % 128),
            );
            try logs.client(client.?, if (index < 4) .udp else .tcp);
        }
        try testing.expectEqual(8, logs.count("event=query"));
        try testing.expectEqual(8, logs.count("src=cache"));
        try testing.expectEqual(0, logs.count("upstream="));
    }
    try testing.expectEqual(allocations, harness.allocator.alloc_index);
    try testing.expect(!harness.allocator.has_induced_failure);
    try harness.stop();
}

fn stressQuery(output: []u8, id: u16, key: u16) ![]const u8 {
    var text: [64]u8 = undefined;
    return query(output, id, try std.fmt.bufPrint(&text, "key{d}.stress.example.", .{key}));
}

fn stressAnswer(packet: *wire.Packet, bytes: []const u8, id: u16, key: u16) !void {
    try packet.parse(bytes);
    try testing.expectEqual(id, packet.header.id);
    try testing.expectEqual(0, packet.header.bits & 15);
    try testing.expectEqual(1, packet.header.counts[1]);
    var expected: [512]u8 = undefined;
    const request = try stressQuery(&expected, id, key);
    var cursor: usize = 12;
    const question = try packet.readQuestion(&cursor);
    var name: wire.Name = undefined;
    try packet.name(&name, question.name);
    try testing.expectEqualSlices(u8, request[12 .. request.len - 4], name.wire());
    try testing.expectEqual(1, question.kind);
    try testing.expectEqual(1, question.class);
    const record = packet.records[0];
    try testing.expect(record.ttl_s > 0);
    try testing.expect(record.ttl_s <= 60);
    try testing.expectEqualSlices(
        u8,
        &.{ 192, 0, 2, 0 },
        bytes[record.data_start..record.data_end],
    );
}

fn fillStressCache(
    harness: *Harness,
    client: system.fd_t,
    logs: *logging.Capture,
    packet: *wire.Packet,
    deadline_ns: u64,
) !void {
    var input: [512]u8 = undefined;
    var upstream: [512]u8 = undefined;
    var response: [512]u8 = undefined;
    var output: [512]u8 = undefined;
    var generation: ?u31 = null;
    for (0..128) |index| {
        try testing.expect(try runtime.nowNs() < deadline_ns);
        logs.* = .{};
        try send(client, try stressQuery(&input, @intCast(index), @intCast(index)));
        const request = try harness.request(&upstream);
        const current = harness.service.forward.sessions[request.session].generation;
        if (generation) |value| try testing.expectEqual(value, current);
        generation = current;
        try send(harness.peer.?, try answer(&response, request.bytes, 0, 1));
        const length = try harness.receive(client, &output);
        try stressAnswer(packet, output[0..length], @intCast(index), @intCast(index));
        try testing.expectEqual(1, logs.count("src=forward"));
        try testing.expectEqual(1, logs.count("upstream_proto=tcp"));
    }
}
