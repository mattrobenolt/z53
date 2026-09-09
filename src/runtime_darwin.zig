//! Single event-thread macOS runtime. All socket calls are nonblocking beneath kqueue.
const std = @import("std");
const system = std.c;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const assert = std.debug.assert;
const builtin = @import("builtin");

pub const address = @import("runtime/address_darwin.zig");
pub const forwarding = @import("runtime/forward.zig");
const upstream = @import("runtime/forward_darwin.zig");
pub const proctor = @import("runtime/kqueue.zig");
const log = @import("runtime/log.zig");
const pipeline = @import("runtime/pipeline.zig");
const config = pipeline.resolver.config;
const tcp = @import("runtime/tcp.zig");
const datagram = @import("runtime/udp_darwin.zig");

const timer_slot = 2 * config.listeners_max;
const client_start = timer_slot + 1;
const send_start = client_start + tcp.clients_max;
pub const upstream_start = send_start + config.listeners_max;

comptime {
    assert(proctor.operations_max == upstream.timer_slot + 1);
}

pub const Error = error{
    SetupFailed,
    RegistrationFailed,
    CompletionFailed,
    InvalidCompletion,
    GenerationExhausted,
    UnresolvedListener,
    SocketFailed,
    BindFailed,
    ListenFailed,
    OutOfMemory,
    HostsLoadFailed,
    EntropyUnavailable,
    Canceled,
    ClockFailed,
    TrustStoreTooLarge,
    TrustStoreLoadFailed,
    TransportFailed,
};

const Listener = struct {
    udp: ?system.fd_t = null,
    tcp: ?system.fd_t = null,
};

pub const Runtime = struct {
    proctor: proctor.Proctor,
    pipeline: pipeline.Pipeline,
    forward: forwarding.Forward,
    upstreams: upstream.Driver,
    listeners: [config.listeners_max]Listener,
    clients: [tcp.clients_max]tcp.Client,
    descriptors: [tcp.clients_max]?system.fd_t,
    responses: [proctor.buffers_max]datagram.Response,
    input: [pipeline.wire.message_bytes_max]u8,
    listener_count: u16,
    state: enum { running, stopping },
    io: Io,
    // Each dispatched event resamples monotonic time; the tick reuses that sample.
    tick_ns: u64,
    // Test-only sendto failure injection: the errno to report and the attempt count.
    test_send_errno: if (builtin.is_test) ?system.E else void,
    test_send_attempts: if (builtin.is_test) u32 else void,
    pub const test_datagram = if (builtin.is_test) datagram else void;

    pub fn init(
        self: *Runtime,
        allocator: Allocator,
        io: Io,
        settings: *const config.Config,
    ) Error!void {
        self.io = io;
        if (builtin.is_test) {
            self.test_send_errno = null;
            self.test_send_attempts = 0;
        }
        self.state = .running;
        self.listener_count = @intCast(settings.listen.len);
        self.listeners = @splat(.{});
        self.descriptors = @splat(null);
        for (&self.clients) |*client| {
            client.state = .vacant;
            client.generation = 0;
        }
        for (&self.responses) |*response| {
            response.listener = null;
            response.state = .ready;
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
        for (settings.listen, 0..) |text, index| {
            var endpoint: address.Address = undefined;
            try endpoint.parse(text);
            self.listeners[index].udp = try endpoint.bind(system.SOCK.DGRAM);
            self.listeners[index].tcp = try endpoint.bind(system.SOCK.STREAM);
            try self.receive(@intCast(index));
            try self.accept(@intCast(index));
        }
        self.tick_ns = try nowNs();
        const now_s = self.tick_ns / std.time.ns_per_s;
        for (self.pipeline.zones.items) |*zone| zone.check_s = now_s;
        try self.proctor.arm(timer_slot, timer_slot, system.EVFILT.TIMER);
    }

    pub fn deinit(self: *Runtime) void {
        self.proctor.deinit();
        self.closeDescriptors();
        self.pipeline.deinit();
        self.forward.deinit();
        self.* = undefined;
    }

    fn closeDescriptors(self: *Runtime) void {
        self.upstreams.deinit();
        for (self.descriptors) |descriptor| {
            if (descriptor) |value| _ = system.close(value);
        }
        for (self.listeners) |listener| {
            if (listener.udp) |descriptor| _ = system.close(descriptor);
            if (listener.tcp) |descriptor| _ = system.close(descriptor);
        }
    }

    pub fn stop(self: *Runtime) Error!void {
        assert(self.state == .running);
        self.state = .stopping;
        try self.proctor.stop();
        // EV_DELETE removes every readiness interest, so pending responses can be dropped here.
        for (&self.responses) |*response| response.listener = null;
    }

    pub fn step(self: *Runtime) Error!bool {
        if (self.state == .stopping) {
            assert(!self.proctor.pending());
            return false;
        }
        const slot = (try self.proctor.next()) orelse return true;
        self.tick_ns = try nowNs();
        if (slot < config.listeners_max) {
            try self.datagramReady(@intCast(slot));
            try self.receive(@intCast(slot));
        } else if (slot < timer_slot) {
            try self.accepted(@intCast(slot - config.listeners_max));
        } else if (slot == timer_slot) {
            self.pipeline.reload(self.io, self.tick_ns / std.time.ns_per_s);
            try self.resumeAccepts();
            try self.proctor.arm(timer_slot, timer_slot, system.EVFILT.TIMER);
        } else if (slot < send_start) {
            try self.clientReady(@intCast(slot - client_start));
        } else if (slot < upstream.operation_start) {
            try self.sendReady(@intCast(slot - send_start));
        } else if (slot == upstream.timer_slot) {
            try self.upstreams.expired(self);
        } else {
            try self.upstreams.ready(self, @intCast(slot - upstream.operation_start));
        }
        try self.upstreams.drive(self);
        return true;
    }

    fn receive(self: *Runtime, index: u16) Error!void {
        try self.proctor.arm(index, @intCast(self.listeners[index].udp.?), system.EVFILT.READ);
    }

    fn accept(self: *Runtime, index: u16) Error!void {
        try self.proctor.arm(
            config.listeners_max + @as(u32, index),
            @intCast(self.listeners[index].tcp.?),
            system.EVFILT.READ,
        );
    }

    fn datagramReady(self: *Runtime, listener: u16) Error!void {
        var source: system.sockaddr.storage = std.mem.zeroes(system.sockaddr.storage);
        var vector: std.posix.iovec = .{ .base = &self.input, .len = self.input.len };
        var message: system.msghdr = .{
            .name = @ptrCast(&source),
            .namelen = @sizeOf(system.sockaddr.storage),
            .iov = @ptrCast(&vector),
            .iovlen = 1,
            .control = null,
            .controllen = 0,
            .flags = 0,
        };
        const count = system.recvmsg(self.listeners[listener].udp.?, &message, 0);
        if (count < 0) {
            switch (std.posix.errno(count)) {
                .AGAIN, .INTR, .CONNRESET => return,
                else => return error.TransportFailed,
            }
        }
        if (message.flags & (system.MSG.TRUNC | system.MSG.CTRUNC) != 0) return;
        const family = datagram.family(&source, message.namelen) catch return;
        if (count > self.input.len) return error.TransportFailed;
        for (&self.responses, 0..) |*response, index| {
            if (response.listener != null) continue;
            if (response.generation == std.math.maxInt(u31)) return error.GenerationExhausted;
            response.generation += 1;
            response.address = source;
            response.address_length = message.namelen;
            response.listener = listener;
            response.state = .reserved;
            response.observation = .{
                .client = log.peer(&source, message.namelen),
                .protocol = .udp,
                .started_ns = nowNs() catch 0,
            };
            const input = self.input[0..@intCast(count)];
            const admission = self.pipeline.begin(
                input,
                &response.output,
                .{ .udp = family },
                self.tick_ns / std.time.ns_per_s,
            ) catch {
                response.listener = null;
                return;
            };
            switch (admission) {
                .drop => response.listener = null,
                .answer => |answer| try self.publishResponse(@intCast(index), input, &answer, null),
                .forward => |zone| {
                    const destination: forwarding.Destination = .{
                        .index = @intCast(index),
                        .generation = response.generation,
                        .transport = .{ .udp = family },
                    };
                    if (self.forward.admit(input, zone, &destination) == null) {
                        const answer = self.pipeline.localFailure(input, &response.output) catch {
                            response.listener = null;
                            return;
                        };
                        try self.publishResponse(@intCast(index), input, &answer, null);
                    }
                },
            }
            return;
        }
        // Pool exhaustion drops only this datagram, with no overflow storage.
    }

    fn publishResponse(
        self: *Runtime,
        index: u16,
        input: []const u8,
        answer: *const pipeline.resolver.Answer,
        selected: ?*const log.Upstream,
    ) Error!void {
        const response = &self.responses[index];
        const listener = response.listener.?;
        response.length = @intCast(answer.bytes.len);
        response.state = .ready;
        self.sendResponse(response);
        if (response.listener != null) try self.armSend(listener);
        self.logAnswer(&response.observation, input, answer, selected);
    }

    fn sendResponse(self: *Runtime, response: *datagram.Response) void {
        const listener = response.listener.?;
        const count = self.sendDatagram(response, listener);
        if (count < 0) {
            switch (std.posix.errno(count)) {
                .AGAIN, .INTR => return,
                else => {}, // Datagram transport errors drop the response, as on Linux.
            }
        }
        response.listener = null;
    }

    fn sendDatagram(self: *Runtime, response: *const datagram.Response, listener: u16) isize {
        if (builtin.is_test) {
            self.test_send_attempts += 1;
            if (self.test_send_errno) |value| {
                system._errno().* = @intFromEnum(value);
                return -1;
            }
        }
        return system.sendto(
            self.listeners[listener].udp.?,
            &response.output,
            response.length,
            0,
            @ptrCast(&response.address),
            response.address_length,
        );
    }

    fn armSend(self: *Runtime, listener: u16) Error!void {
        const slot = send_start + @as(u32, listener);
        if (self.proctor.registrations[slot] != null) return;
        try self.proctor.arm(slot, @intCast(self.listeners[listener].udp.?), system.EVFILT.WRITE);
    }

    fn sendReady(self: *Runtime, listener: u16) Error!void {
        // One shared write filter per socket; response slots never overwrite its udata.
        for (&self.responses) |*response| {
            if (response.listener != listener) continue;
            if (response.state == .reserved) continue;
            self.sendResponse(response);
            if (response.listener != null) {
                try self.armSend(listener);
                return;
            }
        }
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
                    if (response.listener == null) return error.InvalidCompletion;
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
                self.tick_ns / std.time.ns_per_s,
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
                .udp => try self.publishResponse(destination.index, input, &answer, upstream_value),
            }
            if (transaction.completion == .response)
                self.forward.sessions[transaction.completion.response].transaction = null;
            transaction.state = .free;
        }
    }

    fn freeClient(self: *const Runtime) ?u16 {
        for (self.descriptors, 0..) |descriptor, index| {
            if (descriptor == null) return @intCast(index);
        }
        return null;
    }

    fn resumeAccepts(self: *Runtime) Error!void {
        if (self.freeClient() == null) return;
        for (0..self.listener_count) |index| {
            if (self.proctor.registrations[config.listeners_max + index] != null) continue;
            try self.accept(@intCast(index));
        }
    }

    fn accepted(self: *Runtime, listener: u16) Error!void {
        const index = self.freeClient() orelse return;
        var source: system.sockaddr.storage = undefined;
        var length: system.socklen_t = @sizeOf(system.sockaddr.storage);
        const descriptor = system.accept(
            self.listeners[listener].tcp.?,
            @ptrCast(&source),
            &length,
        );
        if (descriptor < 0) {
            switch (std.posix.errno(descriptor)) {
                .AGAIN, .INTR, .CONNABORTED => try self.accept(listener),
                // The timer retries admission without a hot readiness loop under quotas.
                .MFILE, .NFILE, .NOBUFS, .NOMEM => {},
                else => return error.TransportFailed,
            }
            return;
        }
        self.descriptors[index] = descriptor;
        try address.prepare(descriptor);
        if (self.clients[index].generation == std.math.maxInt(u31))
            return error.GenerationExhausted;
        self.clients[index].reset();
        self.clients[index].observation.client = log.peer(&source, length);
        try self.armClient(index);
        if (self.freeClient() != null) try self.accept(listener);
    }

    fn armClient(self: *Runtime, index: u16) Error!void {
        if (self.clients[index].phase == .waiting) return;
        const filter: i16 = if (self.clients[index].phase == .response)
            system.EVFILT.WRITE
        else
            system.EVFILT.READ;
        try self.proctor.arm(
            client_start + @as(u32, index),
            @intCast(self.descriptors[index].?),
            filter,
        );
    }

    fn clientReady(self: *Runtime, index: u16) Error!void {
        const client = &self.clients[index];
        const descriptor = self.descriptors[index].?;
        const count = switch (client.phase) {
            .waiting => return error.InvalidCompletion,
            .prefix, .body => system.recv(
                descriptor,
                client.input[client.offset..].ptr,
                client.length - client.offset,
                0,
            ),
            .response => system.send(
                descriptor,
                client.output[client.offset..].ptr,
                client.length - client.offset,
                0,
            ),
        };
        if (count < 0) {
            switch (std.posix.errno(count)) {
                .AGAIN, .INTR => return self.armClient(index),
                else => return self.closeClient(index),
            }
        }
        switch (client.phase) {
            .waiting => return error.InvalidCompletion,
            .response => client.sent(@intCast(count)) catch return self.closeClient(index),
            .prefix, .body => {
                const query = client.received(@intCast(count)) catch
                    return self.closeClient(index);
                if (query) |bytes| {
                    try self.queryClient(index, bytes);
                    if (self.descriptors[index] == null) return;
                }
            },
        }
        try self.armClient(index);
    }

    fn queryClient(self: *Runtime, index: u16, bytes: []const u8) Error!void {
        const client = &self.clients[index];
        client.observation.protocol = .tcp;
        client.observation.started_ns = nowNs() catch 0;
        const admission = self.pipeline.begin(
            bytes,
            client.output[2..],
            .tcp,
            self.tick_ns / std.time.ns_per_s,
        ) catch return self.closeClient(index);
        switch (admission) {
            .drop => return self.closeClient(index),
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
                    const answer = self.pipeline.localFailure(bytes, client.output[2..]) catch
                        return self.closeClient(index);
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
        // Called only after consuming the one-shot event. No queued event refers to this fd.
        assert(self.proctor.registrations[client_start + @as(u32, index)] == null);
        _ = system.close(self.descriptors[index].?);
        self.descriptors[index] = null;
        self.clients[index].state = .vacant;
        try self.resumeAccepts();
    }
};

pub fn now() error{ClockFailed}!u64 {
    var timestamp: system.timespec = undefined;
    if (system.clock_gettime(system.CLOCK.MONOTONIC, &timestamp) < 0) return error.ClockFailed;
    if (timestamp.sec < 0) return error.ClockFailed;
    return @intCast(timestamp.sec);
}

pub fn nowNs() error{ClockFailed}!u64 {
    var timestamp: system.timespec = undefined;
    if (system.clock_gettime(system.CLOCK.MONOTONIC, &timestamp) < 0) return error.ClockFailed;
    if (timestamp.sec < 0) return error.ClockFailed;
    const seconds: u64 = @intCast(timestamp.sec);
    if (seconds > std.math.maxInt(u64) / std.time.ns_per_s - 86400) return error.ClockFailed;
    if (timestamp.nsec < 0) return error.ClockFailed;
    if (timestamp.nsec >= std.time.ns_per_s) return error.ClockFailed;
    return seconds * std.time.ns_per_s + @as(u64, @intCast(timestamp.nsec));
}

comptime {
    // The 40 MiB fixed-storage cap excludes cache entries and packets; hosts tables
    // and configuration are bounded separately.
    assert(
        @sizeOf(Runtime) + pipeline.zone_storage_bytes_max <=
            40 * 1024 * 1024,
    );
    assert(
        @sizeOf(forwarding.Forward) + @sizeOf(upstream.Driver) <= forwarding.storage_bytes_max,
    );
}
