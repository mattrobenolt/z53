const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const config = runtime.pipeline.resolver.config;
const wire = runtime.pipeline.wire;
const forwarding = runtime.forward;
const logging = @import("runtime_log.zig");

const Fixture = struct {
    forward: *forwarding.Forward,
    workspace: *runtime.pipeline.Pipeline,
    zones: [2]config.Zone,
    settings: config.Config,
    logs: logging.Capture,

    fn init(self: *Fixture, maximum: u32) !void {
        self.forward = try testing.allocator.create(forwarding.Forward);
        errdefer testing.allocator.destroy(self.forward);
        self.workspace = try testing.allocator.create(runtime.pipeline.Pipeline);
        errdefer testing.allocator.destroy(self.workspace);
        self.zones = .{
            .{ .suffix = ".", .max_fails = maximum, .cache = null, .upstreams = &.{
                .{ .address = "127.0.0.1:10001" },
                .{ .address = "127.0.0.1:10001", .force_tcp = true },
            } },
            .{ .suffix = "other.", .max_fails = maximum, .cache = null, .upstreams = &.{
                .{ .address = "127.0.0.1:10001" },
            } },
        };
        self.settings = .{ .zones = &self.zones };
        try self.forward.init(testing.io, &self.settings);
        errdefer self.forward.deinit();
        try self.workspace.init(testing.allocator, testing.io, &self.settings);
        self.logs = .{};
        self.forward.logger.sink = self.logs.sink();
    }

    fn deinit(self: *Fixture) void {
        self.workspace.deinit();
        self.forward.deinit();
        testing.allocator.destroy(self.workspace);
        testing.allocator.destroy(self.forward);
        self.* = undefined;
    }

    fn client(self: *Fixture, zone: u16) u16 {
        const query = [_]u8{ 0, 42, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1 };
        return self.forward.admit(&query, zone, &.{
            .index = 0,
            .generation = 1,
            .transport = .{ .udp = .ipv4 },
        }).?;
    }

    fn failure(self: *Fixture, endpoint: u16, now_ns: u64) void {
        self.forward.sessions[0].endpoint = endpoint;
        self.forward.sessions[0].transport = self.forward.protocols[endpoint].?;
        self.forward.failedExchange(0, .transport, now_ns);
    }

    fn response(self: *Fixture, session_index: u16, rcode: u8) !void {
        const session = &self.forward.sessions[session_index];
        @memcpy(session.input[0..session.length], session.output[0..session.length]);
        session.input[4] |= 0x80;
        session.input[5] = rcode;
        try testing.expect(self.forward.admitted(session_index, .{
            .endpoint = session.endpoint,
            .generation = session.generation,
        }, self.workspace));
        self.forward.accepted(session_index, 1_000_000_000);
    }
};

// SPEC §§3.6, 4, 7: thresholds saturate and zero disables exclusion.
// Endpoint identity includes its zone.
test "health thresholds one two zero maximum and isolated endpoint counters" {
    for ([_]u32{ 1, 2, 0, std.math.maxInt(u32) }) |maximum| {
        var fixture: Fixture = undefined;
        try fixture.init(maximum);
        defer fixture.deinit();
        const forward = fixture.forward;
        if (maximum == std.math.maxInt(u32)) forward.health[0].failures = maximum - 2;
        fixture.failure(0, 100);
        try testing.expectEqual(maximum == 1, forward.down(0));
        fixture.failure(0, 200);
        try testing.expectEqual(maximum != 0, forward.down(0));
        try testing.expectEqual(0, forward.health[1].failures);
        try testing.expectEqual(0, forward.health[config.upstreams_max].failures);
        try testing.expectEqual(
            @as(usize, if (maximum == 0) 0 else 1),
            fixture.logs.count("state=down"),
        );
        fixture.failure(0, 300);
        if (maximum == std.math.maxInt(u32))
            try testing.expectEqual(maximum, forward.health[0].failures);
        if (maximum == 0) {
            try testing.expectEqual(null, forward.probeDeadline());
            try testing.expectEqual(null, forward.probe(std.math.maxInt(u64)));
        } else {
            const due_ns: u64 = if (maximum == 1) 500_000_100 else 500_000_200;
            try testing.expectEqual(@as(?u64, due_ns), forward.probeDeadline());
        }
        const transaction = fixture.client(0);
        const selected = forward.select(transaction, 1000).?;
        try testing.expectEqual(
            @as(u16, if (maximum == 0) 0 else 1),
            forward.sessions[selected.session].endpoint,
        );
        const other = fixture.client(1);
        try testing.expectEqual(
            config.upstreams_max,
            forward.sessions[forward.select(other, 1000).?.session].endpoint,
        );
    }
}

// SPEC §§3.6, 3.7: an all-down sequence exhausts without a random known-down retry.
test "health all down selection and local cancellation non penalties" {
    var fixture: Fixture = undefined;
    try fixture.init(1);
    defer fixture.deinit();
    const forward = fixture.forward;
    fixture.failure(0, 0);
    fixture.failure(1, 0);
    const transaction = fixture.client(0);
    try testing.expectEqual(null, forward.select(transaction, 1));
    try testing.expectEqual(.exhausted, forward.transactions[transaction].completion);
    for ([_]forwarding.Failure{ .local, .cancelled }) |failure| {
        forward.failedExchange(0, failure, 1000);
        try testing.expectEqual(1, forward.health[1].failures);
        try testing.expectEqual(@as(?u64, 500_000_000), forward.probeDeadline());
    }
    try testing.expectEqual(2, fixture.logs.count("event=upstream_health"));
}

// SPEC §§3.6, 4: every admitted RCODE resets consecutive failures and restores a probe once.
test "health probe root RD fresh secure ID admission rcodes and restoration" {
    for ([_]u8{ 0, 2, 5 }) |rcode| {
        var fixture: Fixture = undefined;
        try fixture.init(1);
        defer fixture.deinit();
        const forward = fixture.forward;
        fixture.failure(0, 0);
        try testing.expectEqual(null, forward.probe(499_999_999));
        const transaction = forward.probe(500_000_000).?;
        try testing.expectEqual(@as(u16, 0), forward.transactions[transaction].purpose.probe);
        const selected = forward.select(transaction, 500_000_000).?;
        var random = forward.random;
        const identifier = random.random().int(u16);
        try forward.prepare(selected.session, fixture.workspace);
        const session = &forward.sessions[selected.session];
        try testing.expectEqual(identifier, session.identifier);
        try testing.expectEqual(.udp, session.transport);
        const packet = &fixture.workspace.request_packet;
        try packet.parse(session.output[2..session.length]);
        try testing.expect(packet.header.has(.recursion_desired));
        var request: runtime.pipeline.resolver.Request = undefined;
        try request.init(packet);
        try testing.expectEqual(2, @intFromEnum(request.kind));
        try testing.expectEqualSlices(u8, &.{0}, request.name.bytes[0..request.name.length]);
        const deadline_ns = session.deadline_ns;
        @memcpy(session.input[0..session.length], session.output[0..session.length]);
        session.input[4] |= 0x80;
        try rejected(&fixture, selected.session);
        try testing.expectEqual(deadline_ns, session.deadline_ns);
        try fixture.response(selected.session, rcode);
        try testing.expectEqual(0, forward.health[0].failures);
        try testing.expectEqual(.deliver, forward.transactions[transaction].state);
        forward.finishProbe(transaction);
        try testing.expectEqual(null, forward.health[0].probe);
        try testing.expectEqual(null, forward.probeDeadline());
        try testing.expectEqual(1, fixture.logs.count("state=restored failures=0"));
        try testing.expectEqual(0, fixture.logs.count("event=query"));
        try fixture.logs.contains("upstream=127.0.0.1:10001 upstream_proto=udp");
    }
}

fn rejected(fixture: *Fixture, index: u16) !void {
    const forward = fixture.forward;
    const session = &forward.sessions[index];
    for ([_]enum { endpoint, generation, identifier, question }{
        .endpoint, .generation, .identifier, .question,
    }) |mismatch| {
        var peer = .{ .endpoint = session.endpoint, .generation = session.generation };
        switch (mismatch) {
            .endpoint => peer.endpoint += 1,
            .generation => peer.generation += 1,
            .identifier => session.input[2] ^= 1,
            .question => session.input[17] ^= 1,
        }
        try testing.expect(!forward.admitted(index, .{
            .endpoint = peer.endpoint,
            .generation = peer.generation,
        }, fixture.workspace));
        switch (mismatch) {
            .identifier => session.input[2] ^= 1,
            .question => session.input[17] ^= 1,
            else => {},
        }
        try testing.expectEqual(1, forward.health[0].failures);
        try testing.expectEqual(0, fixture.logs.count("state=restored"));
    }
}

// SPEC §§1.3, 3.6: shared pools bound probes and pressure defers deadlines.
// The cursor rotates fairly.
test "health probe pressure fairness client retention and forced TCP" {
    var fixture: Fixture = undefined;
    try fixture.init(1);
    defer fixture.deinit();
    const forward = fixture.forward;
    fixture.failure(0, 0);
    fixture.failure(1, 0);
    fixture.failure(config.upstreams_max, 0);
    for (&forward.transactions) |*transaction| transaction.state = .active;
    try testing.expectEqual(null, forward.probe(500_000_000));
    try testing.expectEqual(@as(?u64, 510_000_000), forward.probeDeadline());
    for (&forward.transactions) |*transaction| transaction.state = .free;
    const first = forward.probe(510_000_000).?;
    const second = forward.probe(510_000_000).?;
    try testing.expectEqual(@as(u16, 1), forward.transactions[first].purpose.probe);
    try testing.expectEqual(
        @as(u16, config.upstreams_max),
        forward.transactions[second].purpose.probe,
    );
    try testing.expectEqual(null, forward.probe(510_000_000));
    try testing.expectEqual(null, forward.probeDeadline());
    const selected = forward.select(first, 510_000_000).?;
    try testing.expectEqual(.tcp, forward.sessions[selected.session].transport);
    try forward.prepare(selected.session, fixture.workspace);
    try fixture.response(selected.session, 5);
    forward.finishProbe(first);
    const third = forward.probe(510_000_000).?;
    try testing.expectEqual(@as(u16, 0), forward.transactions[third].purpose.probe);
    // A delivered client still owns its session. A probe cannot replace its frame.
    for (&forward.sessions, 0..) |*session, index| {
        session.state = .idle;
        session.transaction = @intCast(index);
    }
    try testing.expectEqual(null, forward.select(third, 510_000_000));
    try testing.expectEqual(.local_failure, forward.transactions[third].completion);
    try testing.expectEqual(1, forward.health[0].failures);
    forward.finishProbe(third);
    try testing.expect(forward.probeDeadline().? > 510_000_000);
}

// SPEC §3.6: an ordinary admitted response resets a partial failure streak without a transition.
test "health client response resets partial failure streak for every error rcode" {
    for ([_]u8{ 0, 2, 5 }) |rcode| {
        var fixture: Fixture = undefined;
        try fixture.init(2);
        defer fixture.deinit();
        fixture.failure(0, 0);
        const transaction = fixture.client(0);
        const selected = fixture.forward.select(transaction, 1).?;
        try fixture.forward.prepare(selected.session, fixture.workspace);
        try fixture.response(selected.session, rcode);
        try testing.expectEqual(0, fixture.forward.health[0].failures);
        try testing.expectEqual(0, fixture.logs.count("event=upstream_health"));
        try testing.expect(fixture.forward.transactions[transaction].completion == .response);
        try testing.expectEqual(1, fixture.forward.transactions[transaction].cursor);
    }
}

// SPEC §§1.3, 3.6: full sessions defer all due endpoints, not just the first failed selection.
test "health full sessions defer overdue timers and retain fair cursor" {
    var fixture: Fixture = undefined;
    try fixture.init(1);
    defer fixture.deinit();
    const forward = fixture.forward;
    fixture.failure(0, 0);
    fixture.failure(1, 0);
    fixture.failure(config.upstreams_max, 0);
    for (&forward.sessions) |*session| session.state = .connecting;
    try testing.expectEqual(null, forward.probe(500_000_000));
    try testing.expectEqual(@as(?u64, 510_000_000), forward.probeDeadline());
    try testing.expectEqual(1, forward.probe_cursor);
    for (0..32) |_| try testing.expectEqual(null, forward.probe(500_000_000));
    try testing.expectEqual(1, forward.probe_cursor);
    for (&forward.health) |*health| try testing.expectEqual(null, health.probe);
    forward.sessions[1].state = .vacant;
    const transaction = forward.probe(510_000_000).?;
    try testing.expectEqual(@as(u16, 1), forward.transactions[transaction].purpose.probe);
    try testing.expectEqual(1, forward.health[0].failures);
    try testing.expectEqual(1, forward.health[1].failures);
}

// SPEC §§1.3, 3.6: supported, health-enabled endpoints retain stable sparse identifiers.
test "health configured candidates exclude disabled zones and preserve sparse fair order" {
    var zones = [_]config.Zone{
        .{ .suffix = ".", .max_fails = 0, .upstreams = &.{.{ .address = "127.0.0.1:10001" }} },
        .{ .suffix = "one.", .upstreams = &.{
            .{ .address = "127.0.0.1:10001" },
            .{ .address = "unsupported.example:53" },
            .{ .address = "127.0.0.1:10001", .force_tcp = true },
        } },
        .{ .suffix = "two.", .upstreams = &.{.{ .address = "127.0.0.1:10001" }} },
    };
    const settings: config.Config = .{ .zones = &zones };
    const forward = try testing.allocator.create(forwarding.Forward);
    defer testing.allocator.destroy(forward);
    try forward.init(testing.io, &settings);
    defer forward.deinit();
    try testing.expectEqualSlices(u16, &.{ 16, 18, 32 }, forward.probe_endpoints.constSlice());
    for (forward.probe_endpoints.constSlice()) |endpoint| forward.health[endpoint].failures = 2;
    try testing.expectEqual(@as(?u64, 0), forward.probeDeadline());
    const first = forward.probe(0).?;
    const second = forward.probe(0).?;
    try testing.expectEqual(@as(u16, 16), forward.transactions[first].purpose.probe);
    try testing.expectEqual(@as(u16, 18), forward.transactions[second].purpose.probe);
    try testing.expectEqual(null, forward.probe(0));
    try testing.expectEqual(null, forward.probeDeadline());
    finishLocalProbe(forward, first);
    const third = forward.probe(500_000_000).?;
    try testing.expectEqual(@as(u16, 32), forward.transactions[third].purpose.probe);
    finishLocalProbe(forward, second);
    const fourth = forward.probe(500_000_000).?;
    try testing.expectEqual(@as(u16, 16), forward.transactions[fourth].purpose.probe);
    finishLocalProbe(forward, third);
    finishLocalProbe(forward, fourth);
}

fn finishLocalProbe(forward: *forwarding.Forward, index: u16) void {
    forward.transactions[index].completion = .local_failure;
    forward.transactions[index].state = .deliver;
    forward.finishProbe(index);
}

// SPEC §§3.6, 5.1: empty configurations and disabled health have no probe candidates.
test "health empty candidate lists do not wrap or retain an earlier configuration" {
    var fixture: Fixture = undefined;
    try fixture.init(1);
    defer fixture.deinit();
    const forward = fixture.forward;
    try testing.expectEqual(3, forward.probe_endpoints.len);
    forward.deinit();
    for (&fixture.zones) |*zone| zone.max_fails = 0;
    try forward.init(testing.io, &fixture.settings);
    try testing.expectEqual(0, forward.probe_endpoints.len);
    try testing.expectEqual(null, forward.probe(std.math.maxInt(u64)));
    try testing.expectEqual(null, forward.probeDeadline());
    forward.deinit();
    const empty: config.Config = .{ .zones = &.{} };
    try forward.init(testing.io, &empty);
    try testing.expectEqual(0, forward.probe_endpoints.len);
    try testing.expectEqual(null, forward.probe(std.math.maxInt(u64)));
    try testing.expectEqual(null, forward.probeDeadline());
}

// SPEC §§1.3, 5.1: every configured slot fits, including the final capacity-derived length.
test "health candidate list admits the complete endpoint capacity" {
    const forward = try testing.allocator.create(forwarding.Forward);
    defer testing.allocator.destroy(forward);
    const upstreams: [config.upstreams_max]config.Upstream = @splat(.{
        .address = "127.0.0.1:10001",
    });
    var suffixes: [config.zones_max][16]u8 = undefined;
    var zones: [config.zones_max]config.Zone = undefined;
    for (&zones, 0..) |*zone, index| {
        zone.* = .{
            .suffix = try std.fmt.bufPrint(&suffixes[index], "zone{d}.", .{index}),
            .upstreams = &upstreams,
        };
    }
    const settings: config.Config = .{ .zones = &zones };
    try forward.init(testing.io, &settings);
    defer forward.deinit();
    try testing.expectEqual(forwarding.endpoints_max, forward.probe_endpoints.len);
    for (forward.probe_endpoints.constSlice(), 0..) |endpoint, index| {
        try testing.expectEqual(index, endpoint);
    }
    try testing.expectEqual(null, forward.probe(0));
    try testing.expectEqual(0, forward.probe_cursor);
}

// SPEC §3.6: backend allocation and buffer failures remain local, unlike certificate rejection.
test "health TLS typed crypto and certificate classification" {
    const tls = forwarding.tls;
    try testing.expectEqual(error.LocalFailure, tls.classify(error.LibcryptoFailed));
    try testing.expectEqual(error.LocalFailure, tls.classify(error.HandshakeBufferTooShort));
    try testing.expectEqual(error.TransportFailure, tls.classify(error.CertificateHostMismatch));
    try testing.expectEqual(error.TransportFailure, tls.classify(error.CertificateIssuerNotFound));
}

// SPEC §§1.1, 1.2, 3.6: local close retains probe identity until socket retirement.
test "health probe local retirement and idle close preserve counters" {
    var fixture: Fixture = undefined;
    try fixture.init(1);
    defer fixture.deinit();
    const forward = fixture.forward;
    fixture.failure(0, 0);
    const transaction = forward.probe(500_000_000).?;
    const selected = forward.select(transaction, 500_000_000).?;
    const session = &forward.sessions[selected.session];
    forward.localCompletion(selected.session, .close, 500_000_000);
    try testing.expectEqual(.active, forward.transactions[transaction].state);
    try testing.expectEqual(transaction, forward.health[0].probe.?);
    session.state = .cancelling;
    session.disposition = .retire;
    forward.closed(selected.session, 600_000_000);
    try testing.expectEqual(.deliver, forward.transactions[transaction].state);
    try testing.expectEqual(1, forward.health[0].failures);
    forward.finishProbe(transaction);
    session.state = .cancelling;
    forward.closed(selected.session, 700_000_000);
    try testing.expectEqual(1, forward.health[0].failures);
    try testing.expectEqual(1, fixture.logs.count("event=upstream_health"));
}
