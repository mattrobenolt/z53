//! Bounded literal UDP and TCP exchanges. Backends own socket and cancellation barriers.
const std = @import("std");
const Io = std.Io;
const IpAddress = Io.net.IpAddress;
const assert = std.debug.assert;
const DefaultCsprng = std.Random.DefaultCsprng;
const time = std.time;

const ArrayBuffer = @import("../array_buffer.zig").ArrayBuffer;
pub const log = @import("log.zig");
const ownership = @import("ownership.zig");
const FailureReason = @import("failure.zig").Reason;
const pipeline = @import("pipeline.zig");
const config = pipeline.resolver.config;
const wire = pipeline.wire;
pub const tls = @import("tls.zig");
const udp = @import("udp.zig");

pub const transactions_max = 32;
pub const sessions_max = 32;
pub const endpoints_max = config.zones_max * config.upstreams_max;
pub const probes_max = 2;
pub const storage_bytes_max = 12 * 1024 * 1024;

const ProbeEndpoints = ArrayBuffer(u16, endpoints_max);

pub const Transport = enum { udp, tcp, tls };

pub const Destination = struct {
    index: u16,
    generation: u31,
    transport: pipeline.Transport,
};

pub const Failure = enum { transport, local, cancelled };

pub const Health = struct {
    failures: u32 = 0,
    due_ns: u64 = 0,
    probe: ?u16 = null,
};

pub const Transaction = struct {
    state: enum { free, ready, active, deliver } = .free,
    purpose: union(enum) {
        client: Destination,
        probe: u16,
    },
    zone: u16,
    cursor: u16,
    length: u32,
    completion: union(enum) {
        response: u16,
        exhausted,
        local_failure,
    },
    input: [wire.message_bytes_max]u8,
};

pub const Session = struct {
    state: enum {
        vacant,
        connecting,
        writing,
        read_prefix,
        read_body,
        read_datagram,
        tls_read,
        tls_write,
        idle,
        cancelling,
    } = .vacant,
    tls: tls.Connection,
    transport: Transport = .tcp,
    transaction: ?u16 = null,
    endpoint: u16,
    generation: u31 = 0,
    deadline_ns: u64,
    offset: u32,
    length: u32,
    identifier: u16,
    failure_reason: FailureReason,
    disposition: enum { retry, replace, retire } = .retire,
    input: [wire.message_bytes_max + wire.frame_prefix_bytes]u8,
    output: [wire.message_bytes_max + wire.frame_prefix_bytes]u8,

    pub fn prefix(self: *Session) void {
        self.state = .read_prefix;
        self.offset = 0;
        self.length = wire.frame_prefix_bytes;
    }

    pub fn startRead(self: *Session) void {
        if (self.transport != .udp) return self.prefix();
        self.state = .read_datagram;
        self.offset = wire.frame_prefix_bytes;
        self.length = self.input.len;
    }

    pub fn received(self: *Session, count: i32) enum { progress, frame, failed } {
        if (self.state == .read_datagram) {
            if (count < 0) return .failed;
            if (@as(u32, @intCast(count)) > self.input.len - wire.frame_prefix_bytes)
                return .failed;
            self.length = @as(u32, @intCast(count)) + wire.frame_prefix_bytes;
            return .frame;
        }
        switch (self.state) {
            .read_prefix, .read_body => {},
            else => unreachable,
        }
        if (count <= 0) return .failed;
        if (@as(u32, @intCast(count)) > self.length - self.offset) return .failed;
        self.offset += @intCast(count);
        if (self.offset < self.length) return .progress;
        if (self.state == .read_body) return .frame;
        const length: u32 = wire.integer(u16, self.input[0..wire.frame_prefix_bytes]);
        if (length < wire.header_bytes) return .failed;
        self.state = .read_body;
        self.length = length + wire.frame_prefix_bytes;
        return .progress;
    }
};

pub const Selection = struct {
    session: u16,
    action: enum { connect, reuse, replace },
};

pub const Forward = struct {
    config: *const config.Config,
    support: [config.zones_max]enum { unsupported, supported },
    endpoints: [endpoints_max]IpAddress,
    protocols: [endpoints_max]?Transport,
    health: [endpoints_max]Health,
    probe_endpoints: ProbeEndpoints,
    probe_cursor: ProbeEndpoints.Index,
    probe_retry_ns: u64,
    transactions: [transactions_max]Transaction,
    sessions: [sessions_max]Session,
    random: DefaultCsprng,
    trust: tls.Trust,
    io: Io,
    logger: log.Logger,

    pub fn init(
        self: *Forward,
        io: Io,
        settings: *const config.Config,
    ) (Io.RandomSecureError || tls.TrustError)!void {
        self.config = settings;
        self.io = io;
        self.logger.sink = .{};
        self.trust.bundle = .empty;
        self.support = @splat(.unsupported);
        self.protocols = @splat(null);
        self.health = @splat(.{});
        self.probe_endpoints.clear();
        self.probe_cursor = 0;
        self.probe_retry_ns = 0;
        for (&self.transactions) |*transaction| transaction.state = .free;
        for (&self.sessions) |*session| {
            session.state = .vacant;
            session.transport = .tcp;
            session.transaction = null;
            session.generation = 0;
            session.tls.handshake = null;
        }
        var seed: [DefaultCsprng.secret_seed_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &seed);
        try io.randomSecure(&seed);
        self.random = .init(seed);
        var trust_needed = false;
        for (settings.zones, 0..) |*zone, index| {
            for (zone.upstreams, 0..) |*upstream, cursor| {
                if (upstream.tls != null) trust_needed = true;
                var endpoint: config.Endpoint = undefined;
                upstream.endpoint(&endpoint);
                const position = index * config.upstreams_max + cursor;
                self.endpoints[position] =
                    IpAddress.parse(endpoint.host, endpoint.port) catch continue;
                self.protocols[position] = if (upstream.tls != null)
                    .tls
                else if (upstream.force_tcp) .tcp else .udp;
                if (zone.max_fails != 0) {
                    // Immutable configuration bounds the list and excludes unused endpoint slots.
                    self.probe_endpoints.appendAssumeCapacity(@intCast(position));
                }
                if (cursor == 0) self.support[index] = .supported;
            }
        }
        if (trust_needed) try self.trust.init(io);
    }

    pub fn deinit(self: *Forward) void {
        for (&self.sessions) |*session| {
            if (session.tls.handshake != null) session.tls.deinit();
        }
        self.* = undefined;
    }

    /// The caller reserves its destination before it transfers the original query.
    pub fn admit(
        self: *Forward,
        input: []const u8,
        zone: u16,
        destination: *const Destination,
    ) ?u16 {
        assert(input.len <= wire.message_bytes_max);
        if (self.support[zone] == .unsupported) return null;
        for (&self.transactions, 0..) |*transaction, index| {
            if (transaction.state != .free) continue;
            transaction.state = .ready;
            transaction.purpose = .{ .client = destination.* };
            transaction.zone = zone;
            transaction.cursor = 0;
            transaction.length = @intCast(input.len);
            @memcpy(transaction.input[0..input.len], input);
            return @intCast(index);
        }
        return null;
    }

    pub fn select(self: *Forward, index: u16, now_ns: u64) ?Selection {
        const transaction = &self.transactions[index];
        assert(transaction.state == .ready);
        if (transaction.purpose == .client) {
            const length = self.config.zones[transaction.zone].upstreams.len;
            while (transaction.cursor < length) : (transaction.cursor += 1) {
                const endpoint = transaction.zone * @as(u16, config.upstreams_max) +
                    transaction.cursor;
                if (!self.down(endpoint)) break;
            }
        }
        if (transaction.cursor == self.config.zones[transaction.zone].upstreams.len) {
            transaction.completion = .exhausted;
            transaction.state = .deliver;
            return null;
        }
        const endpoint = transaction.zone * @as(u16, config.upstreams_max) + transaction.cursor;
        const configured = self.protocols[endpoint] orelse {
            // An unavailable transport stops here, without a silent skip past this member.
            transaction.completion = .local_failure;
            transaction.state = .deliver;
            return null;
        };
        const transport: Transport = switch (transaction.purpose) {
            .probe => configured,
            .client => |destination| if (configured == .tls)
                .tls
            else if (destination.transport == .tcp) .tcp else configured,
        };
        const selected = self.selectSession(endpoint, transport, now_ns) orelse {
            if (transaction.purpose == .probe)
                self.probe_retry_ns = now_ns + 10 * std.time.ns_per_ms;
            transaction.completion = .local_failure;
            transaction.state = .deliver;
            return null;
        };
        transaction.cursor += 1;
        transaction.state = .active;
        const session = &self.sessions[selected.session];
        session.transaction = index;
        session.endpoint = endpoint;
        session.transport = transport;
        session.failure_reason = .transport_failure;
        session.deadline_ns = now_ns +
            duration(self.config.zones[transaction.zone].read_timeout_s);
        return selected;
    }

    pub fn down(self: *const Forward, endpoint: u16) bool {
        const maximum = self.config.zones[endpoint / config.upstreams_max].max_fails;
        if (maximum == 0) return false;
        return self.health[endpoint].failures >= maximum;
    }

    /// Only retired transport exchanges penalize their configured endpoint.
    pub fn failedExchange(self: *Forward, index: u16, failure: Failure, now_ns: u64) void {
        if (failure != .transport) return;
        const endpoint = self.sessions[index].endpoint;
        const was_down = self.down(endpoint);
        const health = &self.health[endpoint];
        health.failures +|= 1;
        if (!self.down(endpoint)) return;
        if (was_down) {
            const transaction = self.sessions[index].transaction orelse return;
            if (self.transactions[transaction].purpose != .probe) return;
        }
        const zone = &self.config.zones[endpoint / config.upstreams_max];
        health.due_ns = now_ns + duration(zone.health_check_interval_s);
        if (was_down) return;
        const selected = self.selectedUpstream(index);
        log.health(&self.logger, self.io, &selected, .down, health.failures);
    }

    fn restored(self: *Forward, index: u16) void {
        const endpoint = self.sessions[index].endpoint;
        const was_down = self.down(endpoint);
        self.health[endpoint].failures = 0;
        if (!was_down) return;
        const selected = self.selectedUpstream(index);
        log.health(&self.logger, self.io, &selected, .restored, 0);
    }

    fn probesActive(self: *const Forward) u16 {
        var count: u16 = 0;
        for (self.probe_endpoints.constSlice()) |endpoint| {
            if (self.health[endpoint].probe != null) count += 1;
        }
        assert(count <= probes_max);
        return count;
    }

    pub fn probeDeadline(self: *const Forward) ?u64 {
        if (self.probesActive() == probes_max) return null;
        var nearest: ?u64 = null;
        for (self.probe_endpoints.constSlice()) |endpoint| {
            if (!self.down(endpoint)) continue;
            const health = &self.health[endpoint];
            if (health.probe != null) continue;
            const due_ns = @max(health.due_ns, self.probe_retry_ns);
            nearest = @min(nearest orelse due_ns, due_ns);
        }
        return nearest;
    }

    /// Clients take the shared pools first. Pressure defers probes without an overdue timer loop.
    pub fn probe(self: *Forward, now_ns: u64) ?u16 {
        if (self.probesActive() == probes_max) return null;
        if (now_ns < self.probe_retry_ns) return null;
        for (0..self.probe_endpoints.len) |_| {
            const endpoint = self.probe_endpoints.constSlice()[self.probe_cursor];
            self.probe_cursor += 1;
            if (self.probe_cursor == self.probe_endpoints.len) self.probe_cursor = 0;
            if (!self.down(endpoint)) continue;
            const health = &self.health[endpoint];
            if (health.probe != null) continue;
            if (now_ns < health.due_ns) continue;
            if (self.selectSession(endpoint, self.protocols[endpoint].?, now_ns) == null) {
                self.probe_retry_ns = now_ns + 10 * std.time.ns_per_ms;
                return null;
            }
            for (&self.transactions, 0..) |*transaction, index| {
                if (transaction.state != .free) continue;
                // RFC 1035 §4.1.2: root NS, IN, RD. prepare supplies a fresh secure ID and OPT.
                const query = [_]u8{ 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1 };
                transaction.purpose = .{ .probe = endpoint };
                transaction.zone = endpoint / config.upstreams_max;
                transaction.cursor = endpoint % config.upstreams_max;
                transaction.length = query.len;
                @memcpy(transaction.input[0..query.len], &query);
                transaction.state = .ready;
                health.probe = @intCast(index);
                health.due_ns = now_ns +
                    duration(self.config.zones[transaction.zone].health_check_interval_s);
                return @intCast(index);
            }
            self.probe_retry_ns = now_ns + 10 * time.ns_per_ms;
            return null;
        }
        return null;
    }

    /// Probe completion never enters the client pipeline or its completion logger.
    pub fn finishProbe(self: *Forward, index: u16) void {
        const transaction = &self.transactions[index];
        assert(transaction.state == .deliver);
        const endpoint = transaction.purpose.probe;
        assert(self.health[endpoint].probe == index);
        self.health[endpoint].probe = null;
        if (transaction.completion == .response)
            self.sessions[transaction.completion.response].transaction = null;
        transaction.state = .free;
    }

    fn selectSession(self: *Forward, endpoint: u16, transport: Transport, now_ns: u64) ?Selection {
        var candidate: ?Selection = null;
        for (&self.sessions, 0..) |*session, position| {
            // An accepted response retains its frame until client publication completes.
            if (session.transaction != null) continue;
            switch (session.state) {
                .idle => {
                    if (session.endpoint == endpoint) {
                        if (session.transport == transport) {
                            if (now_ns < session.deadline_ns)
                                return .{ .session = @intCast(position), .action = .reuse };
                        }
                    }
                    if (candidate == null)
                        candidate = .{ .session = @intCast(position), .action = .replace };
                },
                .vacant => candidate = .{ .session = @intCast(position), .action = .connect },
                else => {},
            }
        }
        return candidate;
    }

    pub fn prepare(self: *Forward, index: u16, workspace: *pipeline.Pipeline) wire.Error!void {
        const session = &self.sessions[index];
        const transaction = &self.transactions[session.transaction.?];
        try workspace.request_packet.parse(transaction.input[0..transaction.length]);
        const edns = wire.rewrite.upstreamEdns(&workspace.request_packet);
        session.identifier = self.random.random().int(u16);
        const settings: wire.rewrite.Settings = .{
            .id = session.identifier,
            .opt = .{ .replace = &edns },
        };
        const bytes = try workspace.cache_workspace.rewrite.rewrite(
            &workspace.request_packet,
            session.output[wire.frame_prefix_bytes..],
            &settings,
        );
        if (session.transport == .udp) {
            const family: udp.Family = switch (self.endpoints[session.endpoint]) {
                .ip4 => .ipv4,
                .ip6 => .ipv6,
            };
            if (bytes.len > udp.limit(wire.message_bytes_max, family))
                return error.MessageTooLarge;
        }
        try wire.framePrefix(&session.output, bytes.len);
        // Datagram payloads share the response layout but never send the TCP length prefix.
        session.offset = if (session.transport == .udp) wire.frame_prefix_bytes else 0;
        session.length = @intCast(bytes.len + wire.frame_prefix_bytes);
        if (session.transport == .tls) session.tls.begin(session.length);
    }

    /// Connected peer identity includes its configured endpoint and connection generation.
    pub fn admitted(
        self: *Forward,
        index: u16,
        peer: struct { endpoint: u16, generation: u31 },
        workspace: *pipeline.Pipeline,
    ) bool {
        const session = &self.sessions[index];
        if (peer.endpoint != session.endpoint) return false;
        if (peer.generation != session.generation) return false;
        const response = &workspace.response_packet;
        response.parse(session.input[wire.frame_prefix_bytes..session.length]) catch return false;
        if (response.header.id != session.identifier) return false;
        if (!response.header.has(.response)) return false;
        if (response.header.opcode() != 0) return false;
        if (response.header.counts[0] != 1) return false;
        const transaction = &self.transactions[session.transaction.?];
        workspace.request_packet.parse(transaction.input[0..transaction.length]) catch unreachable;
        var request: pipeline.resolver.Request = undefined;
        request.init(&workspace.request_packet) catch unreachable;
        var cursor: usize = wire.header_bytes;
        const question = response.readQuestion(&cursor) catch return false;
        if (question.kind != request.kind) return false;
        if (question.class != request.class) return false;
        var name: wire.Name = undefined;
        response.name(&name, question.name) catch return false;
        return name.eql(&request.name);
    }

    pub fn sent(self: *Forward, index: u16, count: i32, now_ns: u64) enum { progress, failed } {
        const session = &self.sessions[index];
        if (count <= 0) return .failed;
        if (@as(u32, @intCast(count)) > session.length - session.offset) return .failed;
        if (session.transport == .udp) {
            if (@as(u32, @intCast(count)) != session.length - session.offset) return .failed;
        }
        session.offset += @intCast(count);
        if (session.offset == session.length) {
            const transaction = &self.transactions[session.transaction.?];
            session.deadline_ns = now_ns +
                duration(self.config.zones[transaction.zone].read_timeout_s);
            session.startRead();
        }
        return .progress;
    }

    pub fn connected(self: *Forward, index: u16) tls.Error!void {
        const session = &self.sessions[index];
        if (session.transport != .tls) {
            session.state = .writing;
            return;
        }
        const zone = session.endpoint / config.upstreams_max;
        const cursor = session.endpoint % config.upstreams_max;
        const name = self.config.zones[zone].upstreams[cursor].tls.?.server_name;
        try session.tls.init(self.io, name, &self.trust);
        session.tls.begin(session.length);
    }

    pub fn pumpTls(
        self: *Forward,
        index: u16,
        now_ns: u64,
        workspace: *pipeline.Pipeline,
    ) tls.Error!void {
        const session = &self.sessions[index];
        for (0..8192) |_| {
            switch (try session.tls.next(&session.output)) {
                .write => {
                    session.state = .tls_write;
                    return;
                },
                .read => {
                    session.state = .tls_read;
                    return;
                },
                .request_sent => {
                    const transaction = &self.transactions[session.transaction.?];
                    session.deadline_ns = now_ns +
                        duration(self.config.zones[transaction.zone].read_timeout_s);
                    session.prefix();
                },
                .data => |bytes| {
                    session.state = if (session.offset < 2) .read_prefix else .read_body;
                    const count = @min(bytes.len, session.length - session.offset);
                    @memcpy(session.input[session.offset..][0..count], bytes[0..count]);
                    session.tls.plaintext = bytes[count..];
                    switch (session.received(@intCast(count))) {
                        .failed => return error.TransportFailure,
                        .progress => {},
                        .frame => {
                            if (self.admitted(index, .{
                                .endpoint = session.endpoint,
                                .generation = session.generation,
                            }, workspace)) {
                                self.accepted(index, now_ns);
                                return;
                            }
                            session.prefix();
                        },
                    }
                },
            }
        }
        return error.TransportFailure;
    }

    pub fn accepted(self: *Forward, index: u16, now_ns: u64) void {
        const session = &self.sessions[index];
        const transaction = &self.transactions[session.transaction.?];
        self.restored(index);
        transaction.completion = .{ .response = index };
        transaction.state = .deliver;
        session.state = .idle;
        session.deadline_ns = now_ns + duration(self.config.zones[transaction.zone].conn_expire_s);
        // Delivery consumes the response before the next admission can reuse this session.
    }

    pub fn selectedUpstream(self: *const Forward, index: u16) log.Upstream {
        const session = &self.sessions[index];
        const zone = session.endpoint / config.upstreams_max;
        const cursor = session.endpoint % config.upstreams_max;
        return .{
            .address = self.endpoints[session.endpoint],
            .protocol = switch (session.transport) {
                .udp => .udp,
                .tcp => .tcp,
                .tls => .dot,
            },
            .tls_name = if (session.transport == .tls)
                self.config.zones[zone].upstreams[cursor].tls.?.server_name
            else
                null,
        };
    }

    pub fn failed(self: *Forward, index: u16, reason: FailureReason) void {
        const selected = self.selectedUpstream(index);
        log.failure(&self.logger, self.io, &selected, reason);
    }

    pub fn responseBytes(self: *const Forward, index: u16) []const u8 {
        const session = &self.sessions[index];
        assert(session.state == .idle);
        assert(session.transaction != null);
        return session.input[wire.frame_prefix_bytes..session.length];
    }

    pub fn localCompletion(
        self: *Forward,
        index: u16,
        retention: enum { immediate, close },
        now_ns: u64,
    ) void {
        const session = &self.sessions[index];
        const transaction = &self.transactions[session.transaction.?];
        transaction.completion = .local_failure;
        if (transaction.purpose == .probe)
            self.probe_retry_ns = now_ns + 10 * time.ns_per_ms;
        if (retention == .close) {
            if (transaction.purpose == .probe) return;
        }
        transaction.state = .deliver;
        session.transaction = null;
    }

    pub fn closed(self: *Forward, index: u16, now_ns: u64) void {
        const session = &self.sessions[index];
        assert(session.state == .cancelling);
        if (session.tls.handshake != null) session.tls.deinit();
        session.state = .vacant;
        if (session.transaction) |transaction| {
            if (session.disposition == .retire) {
                if (self.transactions[transaction].purpose == .probe)
                    self.transactions[transaction].state = .deliver;
            }
            if (session.disposition == .retry) {
                self.failedExchange(index, .transport, now_ns);
                const value = &self.transactions[transaction];
                switch (value.purpose) {
                    .client => value.state = .ready,
                    .probe => {
                        value.completion = .exhausted;
                        value.state = .deliver;
                    },
                }
            }
        }
        if (session.disposition != .replace) session.transaction = null;
    }
};

pub fn duration(seconds: f64) u64 {
    assert(seconds >= 0.001);
    assert(seconds <= 86400);
    return @intFromFloat(@ceil(seconds * time.ns_per_s));
}

comptime {
    const endpoint_bytes = @sizeOf(IpAddress) + @sizeOf(?Transport) + @sizeOf(Health);
    const candidates_bytes = @sizeOf(ProbeEndpoints);
    assert(endpoint_bytes * endpoints_max + candidates_bytes <= 64 * endpoints_max);
    assert(@sizeOf(Forward) <= storage_bytes_max);
}

/// The pair retains both linked completions and both explicit cancellation barriers.
pub fn retired(
    first: *const ownership.Ownership,
    second: *const ownership.Ownership,
) bool {
    if (first.state != .idle) return false;
    return second.state == .idle;
}
