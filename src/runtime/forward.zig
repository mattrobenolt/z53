//! #1: bounded literal forced-TCP exchanges. Backends own socket and cancellation barriers.
const std = @import("std");
const pipeline = @import("pipeline.zig");
const config = pipeline.resolver.config;
const wire = pipeline.wire;
const ownership = @import("ownership.zig");
pub const transactions_max = 32;
pub const sessions_max = 32;
pub const endpoints_max = config.zones_max * config.upstreams_max;
pub const storage_bytes_max = 8 * 1024 * 1024;
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
    state: enum { vacant, connecting, writing, read_prefix, read_body, idle, cancelling } = .vacant,
    transaction: ?u16 = null,
    endpoint: u16,
    generation: u31 = 0,
    deadline_ns: u64,
    offset: u32,
    length: u32,
    identifier: u16,
    disposition: enum { retry, replace, retire } = .retire,
    input: [wire.message_bytes_max + 2]u8,
    output: [wire.message_bytes_max + 2]u8,

    pub fn prefix(self: *Session) void {
        self.state = .read_prefix;
        self.offset = 0;
        self.length = 2;
    }

    pub fn received(self: *Session, count: i32) enum { progress, frame, failed } {
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
    transactions: [transactions_max]Transaction,
    sessions: [sessions_max]Session,
    random: std.Random.DefaultCsprng,

    pub fn init(
        self: *Forward,
        io: std.Io,
        settings: *const config.Config,
    ) std.Io.RandomSecureError!void {
        self.config = settings;
        self.support = @splat(.unsupported);
        for (&self.transactions) |*transaction| transaction.state = .free;
        for (&self.sessions) |*session| {
            session.state = .vacant;
            session.transaction = null;
            session.generation = 0;
        }
        var seed: [std.Random.DefaultCsprng.secret_seed_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &seed);
        try io.randomSecure(&seed);
        self.random = .init(seed);
        for (settings.zones, 0..) |*zone, index| {
            for (zone.upstreams, 0..) |*upstream, cursor| {
                if (upstream.tls != null) break;
                if (!upstream.force_tcp) break;
                var endpoint: config.Endpoint = undefined;
                upstream.endpoint(&endpoint);
                self.endpoints[index * config.upstreams_max + cursor] =
                    std.Io.net.IpAddress.parse(endpoint.host, endpoint.port) catch break;
            } else self.support[index] = .supported;
        }
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
        var candidate: ?Selection = null;
        for (&self.sessions, 0..) |*session, position| {
            // An accepted response retains its frame until client publication completes.
            if (session.transaction != null) continue;
            switch (session.state) {
                .idle => {
                    if (session.endpoint == endpoint) {
                        if (now_ns < session.deadline_ns) {
                            candidate = .{ .session = @intCast(position), .action = .reuse };
                            break;
                        }
                    }
                    if (candidate == null)
                        candidate = .{ .session = @intCast(position), .action = .replace };
                },
                .vacant => candidate = .{ .session = @intCast(position), .action = .connect },
                else => {},
            }
        }
        const selected = candidate orelse {
            transaction.completion = .local_failure;
            transaction.state = .deliver;
            return null;
        };
        transaction.cursor += 1;
        transaction.state = .active;
        const session = &self.sessions[selected.session];
        session.transaction = index;
        session.endpoint = endpoint;
        session.deadline_ns = now_ns +
            duration(self.config.zones[transaction.zone].read_timeout_s);
        return selected;
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
        try wire.framePrefix(&session.output, bytes.len);
        session.offset = 0;
        session.length = @intCast(bytes.len + 2);
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
        session.offset += @intCast(count);
        if (session.offset == session.length) {
            const transaction = &self.transactions[session.transaction.?];
            session.deadline_ns = now_ns +
                duration(self.config.zones[transaction.zone].read_timeout_s);
            session.prefix();
        }
        return .progress;
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

    pub fn responseBytes(self: *const Forward, index: u16) []const u8 {
        const session = &self.sessions[index];
        std.debug.assert(session.state == .idle);
        std.debug.assert(session.transaction != null);
        return session.input[2..session.length];
    }

    pub fn closed(self: *Forward, index: u16) void {
        const session = &self.sessions[index];
        std.debug.assert(session.state == .cancelling);
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
