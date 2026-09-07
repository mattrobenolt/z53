//! #1: bounded literal UDP and TCP exchanges. Backends own socket and cancellation barriers.
const std = @import("std");
const pipeline = @import("pipeline.zig");
const config = pipeline.resolver.config;
const wire = pipeline.wire;
const udp = @import("udp.zig");
const ownership = @import("ownership.zig");
pub const log = @import("log.zig");
pub const tls = @import("tls.zig");
pub const transactions_max = 32;
pub const sessions_max = 32;
pub const endpoints_max = config.zones_max * config.upstreams_max;
pub const storage_bytes_max = 12 * 1024 * 1024;
pub const Transport = enum { udp, tcp, tls };
pub const Destination = struct {
    index: u16,
    generation: u31,
    transport: pipeline.Transport,
};
pub const Transaction = struct {
    state: enum { free, ready, active, deliver } = .free,
    destination: Destination,
    zone: u16,
    cursor: u16,
    length: u32,
    completion: union(enum) { response: u16, exhausted, local_failure },
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
    failure_reason: []const u8,
    disposition: enum { retry, replace, retire } = .retire,
    input: [wire.message_bytes_max + 2]u8,
    output: [wire.message_bytes_max + 2]u8,

    pub fn prefix(self: *Session) void {
        self.state = .read_prefix;
        self.offset = 0;
        self.length = 2;
    }

    pub fn startRead(self: *Session) void {
        if (self.transport != .udp) return self.prefix();
        self.state = .read_datagram;
        self.offset = 2;
        self.length = self.input.len;
    }

    pub fn received(self: *Session, count: i32) enum { progress, frame, failed } {
        if (self.state == .read_datagram) {
            if (count < 0) return .failed;
            if (@as(u32, @intCast(count)) > self.input.len - 2) return .failed;
            self.length = @as(u32, @intCast(count)) + 2;
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
        const length: u32 = wire.integer(u16, self.input[0..2]);
        if (length < 12) return .failed;
        self.state = .read_body;
        self.length = length + 2;
        return .progress;
    }
};
pub const Selection = struct { session: u16, action: enum { connect, reuse, replace } };

pub const Forward = struct {
    config: *const config.Config,
    support: [config.zones_max]enum { unsupported, supported },
    endpoints: [endpoints_max]std.Io.net.IpAddress,
    protocols: [endpoints_max]?Transport,
    transactions: [transactions_max]Transaction,
    sessions: [sessions_max]Session,
    random: std.Random.DefaultCsprng,
    trust: tls.Trust,
    io: std.Io,
    logger: log.Sink,

    pub fn init(
        self: *Forward,
        io: std.Io,
        settings: *const config.Config,
    ) (std.Io.RandomSecureError || tls.TrustError)!void {
        self.config = settings;
        self.io = io;
        self.logger = .{};
        self.trust.bundle = .empty;
        self.support = @splat(.unsupported);
        self.protocols = @splat(null);
        for (&self.transactions) |*transaction| transaction.state = .free;
        for (&self.sessions) |*session| {
            session.state = .vacant;
            session.transport = .tcp;
            session.transaction = null;
            session.generation = 0;
            session.tls.handshake = null;
        }
        var seed: [std.Random.DefaultCsprng.secret_seed_length]u8 = undefined;
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
                    std.Io.net.IpAddress.parse(endpoint.host, endpoint.port) catch continue;
                self.protocols[position] = if (upstream.tls != null)
                    .tls
                else if (upstream.force_tcp) .tcp else .udp;
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
        std.debug.assert(input.len <= wire.message_bytes_max);
        if (self.support[zone] == .unsupported) return null;
        for (&self.transactions, 0..) |*transaction, index| {
            if (transaction.state != .free) continue;
            transaction.state = .ready;
            transaction.destination = destination.*;
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
        std.debug.assert(transaction.state == .ready);
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
        const transport: Transport = if (configured == .tls)
            .tls
        else if (transaction.destination.transport == .tcp) .tcp else configured;
        const selected = self.selectSession(endpoint, transport, now_ns) orelse {
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
        session.failure_reason = "transport_failure";
        session.deadline_ns = now_ns +
            duration(self.config.zones[transaction.zone].read_timeout_s);
        return selected;
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
            session.output[2..],
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
        session.offset = if (session.transport == .udp) 2 else 0;
        session.length = @intCast(bytes.len + 2);
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
        response.parse(session.input[2..session.length]) catch return false;
        if (response.header.id != session.identifier) return false;
        if (!response.header.has(.response)) return false;
        if (response.header.opcode() != 0) return false;
        if (response.header.counts[0] != 1) return false;
        const transaction = &self.transactions[session.transaction.?];
        workspace.request_packet.parse(transaction.input[0..transaction.length]) catch unreachable;
        var request: pipeline.resolver.Request = undefined;
        request.init(&workspace.request_packet) catch unreachable;
        var cursor: usize = 12;
        const question = response.readQuestion(&cursor) catch return false;
        if (question.kind != request.kind) return false;
        if (question.class != request.class) return false;
        var name: wire.Name = undefined;
        response.name(&name, question.name) catch return false;
        return name.equal(&request.name);
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

    pub fn failed(self: *const Forward, index: u16, reason: []const u8) void {
        const selected = self.selectedUpstream(index);
        log.failure(&self.logger, self.io, &selected, reason);
    }

    pub fn responseBytes(self: *const Forward, index: u16) []const u8 {
        const session = &self.sessions[index];
        std.debug.assert(session.state == .idle);
        std.debug.assert(session.transaction != null);
        return session.input[2..session.length];
    }

    pub fn closed(self: *Forward, index: u16) void {
        const session = &self.sessions[index];
        std.debug.assert(session.state == .cancelling);
        if (session.tls.handshake != null) session.tls.deinit();
        session.state = .vacant;
        if (session.transaction) |transaction| {
            if (session.disposition == .retry) self.transactions[transaction].state = .ready;
        }
        if (session.disposition != .replace) session.transaction = null;
    }
};

pub fn duration(seconds: f64) u64 {
    std.debug.assert(seconds >= 0.001);
    std.debug.assert(seconds <= 86400);
    return @intFromFloat(@ceil(seconds * std.time.ns_per_s));
}

comptime {
    std.debug.assert(@sizeOf(std.Io.net.IpAddress) <= 64);
    std.debug.assert(@sizeOf(Forward) <= storage_bytes_max);
}

/// The pair retains both linked completions and both explicit cancellation barriers.
pub fn retired(
    first: *const ownership.Ownership,
    second: *const ownership.Ownership,
) bool {
    if (first.state != .idle) return false;
    return second.state == .idle;
}
