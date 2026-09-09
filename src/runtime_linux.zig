//! Single event-thread Linux client runtime. All socket data moves through io_uring.
const std = @import("std");
pub const proctor = @import("runtime/proctor.zig");
pub const tcp = @import("runtime/tcp.zig");
pub const udp = @import("runtime/udp.zig");
pub const pipeline = @import("runtime/pipeline.zig");
pub const address = @import("runtime/address.zig");
pub const forwarding = @import("runtime/forward.zig");
const log = @import("runtime/log.zig");
const upstream = @import("runtime/forward_linux.zig");
const linux = proctor.linux;
const config = pipeline.resolver.config;
const client_start = 33;
const response_start = client_start + tcp.clients_max;
const timer_slot = 32;
pub const Error = error{
    ClockFailed,
    TrustStoreTooLarge,
    TrustStoreLoadFailed,
    TransportFailed,
    SetupFailed,
    SubmissionFailed,
    CompletionFailed,
    RegistrationFailed,
    InvalidCompletion,
    GenerationExhausted,
    OutOfMemory,
    HostsLoadFailed,
    EntropyUnavailable,
    Canceled,
    UnresolvedListener,
    SocketFailed,
    BindFailed,
    ListenFailed,
};
const Listener = struct {
    udp: ?linux.fd_t = null,
    tcp: ?linux.fd_t = null,
    message: linux.msghdr,
};

pub const Runtime = struct {
    proctor: proctor.Proctor,
    pipeline: pipeline.Pipeline,
    forward: forwarding.Forward,
    upstreams: upstream.Driver,
    listeners: [config.listeners_max]Listener,
    clients: [tcp.clients_max]tcp.Client,
    responses: [proctor.buffers_max]udp.Response,
    peers: [tcp.clients_max]struct { address: address.Address, state: enum { lookup, ready } },
    listener_count: u16,
    state: enum { running, stopping } = .running,
    interval: linux.kernel_timespec = .{ .sec = 1, .nsec = 0 },
    io: std.Io,

    /// The caller owns stable startup storage until deinit completes.
    pub fn init(
        self: *Runtime,
        allocator: std.mem.Allocator,
        io: std.Io,
        settings: *const config.Config,
    ) Error!void {
        self.io = io;
        self.state = .running;
        self.interval = .{ .sec = 1, .nsec = 0 };
        self.listener_count = @intCast(settings.listen.len);
        for (&self.listeners) |*listener| {
            listener.udp = null;
            listener.tcp = null;
        }
        for (&self.clients) |*client| {
            client.state = .vacant;
            client.generation = 0;
        }
        for (&self.responses) |*response| {
            response.state = .free;
            response.generation = 0;
        }
        try self.forward.init(io, settings);
        errdefer self.forward.deinit();
        self.upstreams.init();
        try self.pipeline.init(allocator, io, settings);
        errdefer self.pipeline.deinit();
        try self.proctor.init();
        errdefer self.proctor.deinit();
        errdefer self.closeDescriptors();
        self.proctor.ring.register_files_sparse(192) catch
            return error.RegistrationFailed;
        try self.proctor.registerClients();
        for (settings.listen, 0..) |text, index| try self.bindListener(@intCast(index), text);
        for (0..self.listener_count) |index| {
            try self.receive(@intCast(index));
            try self.accept(@intCast(index));
        }
        const now_s = try now();
        for (self.pipeline.zones) |*zone| zone.check_s = now_s;
        try self.timer();
    }

    pub fn deinit(self: *Runtime) void {
        self.proctor.deinit();
        self.closeDescriptors();
        self.pipeline.deinit();
        self.forward.deinit();
        self.* = undefined;
    }

    fn closeDescriptors(self: *Runtime) void {
        for (&self.listeners) |*listener| {
            if (listener.udp) |descriptor| _ = linux.close(descriptor);
            if (listener.tcp) |descriptor| _ = linux.close(descriptor);
        }
    }

    fn bindListener(self: *Runtime, index: u16, text: []const u8) Error!void {
        var endpoint: address.Address = undefined;
        try endpoint.parse(text);
        const listener = &self.listeners[index];
        listener.udp = try endpoint.bind(linux.SOCK.DGRAM);
        listener.tcp = try endpoint.bind(linux.SOCK.STREAM);
        const files = [_]linux.fd_t{ listener.udp.?, listener.tcp.? };
        self.proctor.ring.register_files_update(@as(u32, index) * 2, &files) catch
            return error.RegistrationFailed;
        listener.message = .{
            .name = null,
            .namelen = @sizeOf(linux.sockaddr.storage),
            .iov = undefined,
            .iovlen = 0,
            .control = null,
            .controllen = 0,
            .flags = 0,
        };
    }

    fn receive(self: *Runtime, index: u16) Error!void {
        const token = try self.proctor.arm(index);
        const entry = self.proctor.ring.recvmsg(
            token,
            @as(i32, index) * 2,
            &self.listeners[index].message,
            0,
        ) catch return error.SubmissionFailed;
        entry.flags |= linux.IOSQE_FIXED_FILE | linux.IOSQE_BUFFER_SELECT;
        entry.buf_index = 0;
        entry.ioprio |= linux.IORING_RECV_MULTISHOT;
    }

    fn accept(self: *Runtime, index: u16) Error!void {
        const token = try self.proctor.arm(16 + @as(u32, index));
        const entry = self.proctor.ring.accept_multishot_direct(
            token,
            @as(i32, index) * 2 + 1,
            null,
            null,
            linux.SOCK.NONBLOCK,
        ) catch return error.SubmissionFailed;
        entry.flags |= linux.IOSQE_FIXED_FILE;
    }

    fn timer(self: *Runtime) Error!void {
        const token = try self.proctor.arm(timer_slot);
        _ = self.proctor.ring.timeout(token, &self.interval, 0, 0) catch
            return error.SubmissionFailed;
    }

    pub fn stop(self: *Runtime) Error!void {
        std.debug.assert(self.state == .running);
        self.state = .stopping;
        try self.proctor.stop();
    }

    /// Returns false only after every cancellation and target completion has arrived.
    pub fn step(self: *Runtime) Error!bool {
        if (self.state == .stopping) {
            if (!self.proctor.pending()) return false;
        }
        const completion = (try self.proctor.next()) orelse return true;
        const slot: u32 = @truncate(completion.user_data);
        if (slot >= upstream.operation_start) {
            if (slot == upstream.timer_slot) {
                if (self.state == .running) try self.upstreams.expired(self);
            } else try self.upstreams.completed(self, &completion);
            if (self.state == .running) try self.upstreams.drive(self);
            return true;
        }
        if (completion.user_data & proctor.cancel_bit != 0) return true;
        if (slot < 16) {
            try self.datagram(@intCast(slot), &completion);
        } else if (slot < 32) {
            try self.accepted(@intCast(slot - 16), &completion);
        } else if (slot == timer_slot) {
            if (self.state == .running) {
                if (completion.err() != .TIME) return error.TransportFailed;
                self.pipeline.reload(self.io, try now());
                try self.timer();
            }
        } else if (slot < response_start) {
            try self.clientCompleted(@intCast(slot - client_start), completion.res);
        } else {
            self.responses[slot - response_start].state = .free;
        }
        if (self.state == .running) try self.upstreams.drive(self);
        return true;
    }

    fn datagram(self: *Runtime, index: u16, completion: *const linux.io_uring_cqe) Error!void {
        if (completion.flags & linux.IORING_CQE_F_BUFFER != 0) {
            const buffer: u16 = @intCast(completion.flags >> 16);
            if (buffer >= proctor.buffers_max) return error.InvalidCompletion;
            defer self.proctor.recycle(buffer);
            if (self.state == .running) {
                if (completion.res > 0) {
                    if (completion.res > proctor.buffer_bytes) return error.InvalidCompletion;
                    const bytes = self.proctor.buffers[buffer][0..@intCast(completion.res)];
                    try self.respond(index, bytes);
                }
            }
        }
        if (self.state == .stopping) return;
        if (completion.res < 0) {
            if (completion.err() != .NOBUFS) return error.TransportFailed;
        }
        if (completion.flags & linux.IORING_CQE_F_MORE == 0) try self.receive(index);
    }

    fn respond(self: *Runtime, listener: u16, bytes: []const u8) Error!void {
        const datagram_value = udp.decode(bytes) catch return;
        for (&self.responses, 0..) |*response, index| {
            if (response.state != .free) continue;
            if (response.generation == std.math.maxInt(u31)) return error.GenerationExhausted;
            response.generation += 1;
            response.state = .reserved;
            response.listener = listener;
            response.prepare(&datagram_value, 0);
            response.state = .reserved;
            response.observation = .{
                .client = log.peer(@ptrCast(&response.address), response.message.namelen),
                .protocol = .udp,
                .started_ns = nowNs() catch 0,
            };
            const admission = self.pipeline.begin(
                datagram_value.payload,
                &response.output,
                .{ .udp = datagram_value.family },
                try now(),
            ) catch {
                response.state = .free;
                return;
            };
            switch (admission) {
                .drop => response.state = .free,
                .answer => |answer| try self.sendResponse(
                    @intCast(index),
                    datagram_value.payload,
                    &answer,
                    null,
                ),
                .forward => |zone| {
                    const destination: forwarding.Destination = .{
                        .index = @intCast(index),
                        .generation = response.generation,
                        .transport = .{ .udp = datagram_value.family },
                    };
                    if (self.forward.admit(datagram_value.payload, zone, &destination) == null) {
                        const answer = self.pipeline.localFailure(
                            datagram_value.payload,
                            &response.output,
                        ) catch {
                            response.state = .free;
                            return;
                        };
                        try self.sendResponse(
                            @intCast(index),
                            datagram_value.payload,
                            &answer,
                            null,
                        );
                    }
                },
            }
            return;
        }
        // Bounded overload policy: drop the datagram, never allocate an overflow queue.
    }

    fn sendResponse(
        self: *Runtime,
        index: u16,
        input: []const u8,
        answer: *const pipeline.resolver.Answer,
        selected: ?*const log.Upstream,
    ) Error!void {
        const response = &self.responses[index];
        std.debug.assert(response.state == .reserved);
        response.vector.len = answer.bytes.len;
        response.state = .sending;
        const token = try self.proctor.arm(response_start + @as(u32, index));
        const entry = self.proctor.ring.sendmsg(
            token,
            @as(i32, response.listener) * 2,
            &response.message,
            linux.MSG.NOSIGNAL,
        ) catch return error.SubmissionFailed;
        entry.flags |= linux.IOSQE_FIXED_FILE;
        self.logAnswer(&response.observation, input, answer, selected);
    }

    pub fn deliverForwards(self: *Runtime) Error!void {
        for (&self.forward.transactions, 0..) |*transaction, transaction_index| {
            if (transaction.state != .deliver) continue;
            const destination = switch (transaction.purpose) {
                .client => |destination| destination,
                .probe => {
                    self.forward.finishProbe(@intCast(transaction_index));
                    continue;
                },
            };
            const output: []u8 = switch (destination.transport) {
                .tcp => self.clients[destination.index].output[2..],
                .udp => &self.responses[destination.index].output,
            };
            switch (destination.transport) {
                .tcp => {
                    const client = &self.clients[destination.index];
                    if (client.generation != destination.generation) return error.InvalidCompletion;
                    if (client.phase != .waiting) return error.InvalidCompletion;
                },
                .udp => {
                    const response = &self.responses[destination.index];
                    if (response.generation != destination.generation)
                        return error.InvalidCompletion;
                    if (response.state != .reserved) return error.InvalidCompletion;
                },
            }
            const completion: pipeline.Completion = switch (transaction.completion) {
                .response => |index| .{ .response = self.forward.responseBytes(index) },
                .exhausted => .exhausted,
                .local_failure => .local_failure,
            };
            const answer = self.pipeline.complete(
                transaction.input[0..transaction.length],
                output,
                destination.transport,
                try now(),
                &completion,
            ) catch return error.TransportFailed;
            const selected: ?log.Upstream = if (transaction.completion == .response)
                self.forward.selectedUpstream(transaction.completion.response)
            else
                null;
            const upstream_value = if (selected) |*value| value else null;
            const input = transaction.input[0..transaction.length];
            switch (destination.transport) {
                .tcp => {
                    self.publishClient(destination.index, input, &answer, upstream_value);
                    try self.armClient(destination.index);
                },
                .udp => try self.sendResponse(destination.index, input, &answer, upstream_value),
            }
            if (transaction.completion == .response)
                self.forward.sessions[transaction.completion.response].transaction = null;
            transaction.state = .free;
        }
    }

    fn accepted(self: *Runtime, listener: u16, completion: *const linux.io_uring_cqe) Error!void {
        if (completion.res >= 0) {
            if (completion.res < 32) return error.InvalidCompletion;
            if (completion.res >= 32 + tcp.clients_max) return error.InvalidCompletion;
            if (self.state == .running) try self.addClient(@intCast(completion.res - 32));
        }
        if (self.state == .stopping) return;
        if (completion.res < 0) {
            switch (completion.err()) {
                .MFILE, .NFILE, .NOBUFS, .NOMEM, .CONNABORTED => {},
                else => return error.TransportFailed,
            }
        }
        if (completion.flags & linux.IORING_CQE_F_MORE == 0) {
            for (&self.clients) |*client_value| {
                if (client_value.state != .vacant) continue;
                try self.accept(listener);
                break;
            }
        }
    }

    fn addClient(self: *Runtime, index: u16) Error!void {
        const client_value = &self.clients[index];
        switch (client_value.state) {
            .vacant => {
                if (client_value.generation == std.math.maxInt(u31))
                    return error.GenerationExhausted;
                client_value.reset();
                try self.lookupPeer(index);
            },
            // The kernel can publish the new accept before userspace consumes CLOSE's CQE.
            .closing => client_value.state = .replacing,
            else => return error.InvalidCompletion,
        }
    }

    fn lookupPeer(self: *Runtime, index: u16) Error!void {
        const peer_address = &self.peers[index];
        peer_address.state = .lookup;
        peer_address.address.length = @sizeOf(linux.sockaddr.storage);
        const token = try self.proctor.arm(client_start + @as(u32, index));
        const entry = self.proctor.ring.get_sqe() catch return error.SubmissionFailed;
        // Linux SOCKET_URING_OP_GETSOCKNAME=5, optlen=1 selects the peer.
        // liburing io_uring_prep_cmd_getsockname defines these SQE aliases.
        entry.prep_rw(
            .URING_CMD,
            32 + @as(i32, index),
            @intFromPtr(&peer_address.address.storage),
            0,
            5,
        );
        entry.addr3 = @intFromPtr(&peer_address.address.length);
        entry.splice_fd_in = 1;
        entry.flags = linux.IOSQE_FIXED_FILE;
        entry.user_data = token;
    }

    fn armClient(self: *Runtime, index: u16) Error!void {
        const client_value = &self.clients[index];
        if (client_value.phase == .waiting) return;
        const token = try self.proctor.arm(client_start + @as(u32, index));
        const descriptor: i32 = 32 + @as(i32, index);
        if (client_value.state == .closing) {
            _ = self.proctor.ring.close_direct(token, @intCast(descriptor)) catch
                return error.SubmissionFailed;
            return;
        }
        const entry = switch (client_value.phase) {
            .prefix, .body => self.proctor.ring.recv(
                token,
                descriptor,
                .{ .buffer = client_value.input[client_value.offset..client_value.length] },
                0,
            ),
            .waiting => unreachable,
            .response => self.proctor.ring.send(
                token,
                descriptor,
                client_value.output[client_value.offset..client_value.length],
                linux.MSG.NOSIGNAL,
            ),
        } catch return error.SubmissionFailed;
        entry.flags |= linux.IOSQE_FIXED_FILE;
    }

    fn clientCompleted(self: *Runtime, index: u16, count: i32) Error!void {
        if (self.state == .stopping) return;
        const client_value = &self.clients[index];
        switch (client_value.state) {
            .closing, .replacing => {
                if (count < 0) return error.TransportFailed;
                if (client_value.state == .replacing) {
                    if (client_value.generation == std.math.maxInt(u31))
                        return error.GenerationExhausted;
                    client_value.reset();
                    try self.lookupPeer(index);
                } else client_value.state = .vacant;
                for (0..self.listener_count) |listener| {
                    if (self.proctor.ownership[16 + listener].state != .idle) continue;
                    try self.accept(@intCast(listener));
                }
                return;
            },
            .connected => {},
            .vacant => return error.InvalidCompletion,
        }
        if (self.peers[index].state == .lookup) {
            if (count < 0) return self.closeClient(index);
            const peer_address = &self.peers[index].address;
            client_value.observation.client = log.peer(
                @ptrCast(&peer_address.storage),
                peer_address.length,
            ) orelse
                return self.closeClient(index);
            self.peers[index].state = .ready;
            return self.armClient(index);
        }
        switch (client_value.phase) {
            .waiting => return error.InvalidCompletion,
            .response => client_value.sent(count) catch return self.closeClient(index),
            .prefix, .body => {
                const query = client_value.received(count) catch return self.closeClient(index);
                if (query) |bytes| {
                    try self.queryClient(index, bytes);
                }
            },
        }
        try self.armClient(index);
    }

    fn queryClient(self: *Runtime, index: u16, bytes: []const u8) Error!void {
        const client = &self.clients[index];
        client.observation.protocol = .tcp;
        client.observation.started_ns = nowNs() catch 0;
        const admission = self.pipeline.begin(bytes, client.output[2..], .tcp, try now()) catch {
            client.state = .closing;
            return;
        };
        switch (admission) {
            .drop => client.state = .closing,
            .answer => |answer| self.publishClient(index, bytes, &answer, null),
            .forward => |zone| {
                const destination: forwarding.Destination = .{
                    .index = index,
                    .generation = client.generation,
                    .transport = .tcp,
                };
                if (self.forward.admit(bytes, zone, &destination) != null) {
                    client.phase = .waiting;
                } else {
                    const answer = self.pipeline.localFailure(bytes, client.output[2..]) catch {
                        client.state = .closing;
                        return;
                    };
                    self.publishClient(index, bytes, &answer, null);
                }
            },
        }
    }

    fn publishClient(
        self: *Runtime,
        index: u16,
        input: []const u8,
        answer: *const pipeline.resolver.Answer,
        selected: ?*const log.Upstream,
    ) void {
        const client = &self.clients[index];
        client.respond(answer.bytes.len);
        self.logAnswer(&client.observation, input, answer, selected);
    }

    fn logAnswer(
        self: *Runtime,
        observation: *const log.Query,
        input: []const u8,
        answer: *const pipeline.resolver.Answer,
        selected: ?*const log.Upstream,
    ) void {
        log.completed(
            &self.forward.logger,
            self.io,
            &self.pipeline.response_packet,
            observation,
            input,
            answer,
            selected,
            nowNs() catch observation.started_ns,
        );
    }

    fn closeClient(self: *Runtime, index: u16) Error!void {
        const client_value = &self.clients[index];
        client_value.state = .closing;
        try self.armClient(index);
    }
};

pub fn now() error{ClockFailed}!u64 {
    var timestamp: linux.timespec = undefined;
    const result = linux.clock_gettime(linux.CLOCK.MONOTONIC, &timestamp);
    if (linux.errno(result) != .SUCCESS) return error.ClockFailed;
    if (timestamp.sec < 0) return error.ClockFailed;
    return @intCast(timestamp.sec);
}

pub fn nowNs() error{ClockFailed}!u64 {
    var timestamp: linux.timespec = undefined;
    const result = linux.clock_gettime(linux.CLOCK.MONOTONIC, &timestamp);
    if (linux.errno(result) != .SUCCESS) return error.ClockFailed;
    if (timestamp.sec < 0) return error.ClockFailed;
    const seconds: u64 = @intCast(timestamp.sec);
    if (seconds > std.math.maxInt(u64) / std.time.ns_per_s - 86400) return error.ClockFailed;
    if (timestamp.nsec < 0) return error.ClockFailed;
    if (timestamp.nsec >= std.time.ns_per_s) return error.ClockFailed;
    return seconds * std.time.ns_per_s + @as(u64, @intCast(timestamp.nsec));
}

comptime {
    // SPEC §1.3 excludes cache entry arrays and packets.
    // Hosts tables and configuration also retain separate bounds.
    std.debug.assert(
        @sizeOf(Runtime) + pipeline.zone_storage_bytes_max + proctor.mapping_bytes_max <=
            40 * 1024 * 1024,
    );
    std.debug.assert(
        @sizeOf(forwarding.Forward) + @sizeOf(upstream.Driver) <= forwarding.storage_bytes_max,
    );
}
