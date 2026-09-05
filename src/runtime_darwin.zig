//! Single event-thread macOS runtime. All socket calls are nonblocking beneath kqueue.
const std = @import("std");
const builtin = @import("builtin");
const system = std.c;
pub const proctor = @import("runtime/kqueue.zig");
pub const address = @import("runtime/address_darwin.zig");
const datagram = @import("runtime/udp_darwin.zig");
const tcp = @import("runtime/tcp.zig");
const pipeline = @import("runtime/pipeline.zig");
const config = pipeline.resolver.config;
const timer_slot = 32;
const client_start = 33;
const send_start = client_start + tcp.clients_max;
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
    ClockFailed,
    TransportFailed,
};
const Listener = struct { udp: ?system.fd_t = null, tcp: ?system.fd_t = null };

pub const Runtime = struct {
    proctor: proctor.Proctor,
    pipeline: pipeline.Pipeline,
    listeners: [config.listeners_max]Listener,
    clients: [tcp.clients_max]tcp.Client,
    descriptors: [tcp.clients_max]?system.fd_t,
    responses: [proctor.buffers_max]datagram.Response,
    input: [65535]u8,
    listener_count: u16,
    state: enum { running, stopping },
    io: std.Io,
    // #1: injected errno tests retain real Runtime dispatch and kqueue readiness.
    test_send_errno: if (builtin.is_test) ?system.E else void,
    test_send_attempts: if (builtin.is_test) u32 else void,
    pub const test_datagram = if (builtin.is_test) datagram else void;

    pub fn init(
        self: *Runtime,
        allocator: std.mem.Allocator,
        io: std.Io,
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
        for (&self.clients) |*client| client.state = .vacant;
        for (&self.responses) |*response| response.listener = null;
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
        const now_s = try now();
        for (self.pipeline.zones) |*zone| zone.check_s = now_s;
        try self.proctor.arm(timer_slot, timer_slot, system.EVFILT.TIMER);
    }

    pub fn deinit(self: *Runtime) void {
        self.proctor.deinit();
        self.closeDescriptors();
        self.pipeline.deinit();
        self.* = undefined;
    }

    fn closeDescriptors(self: *Runtime) void {
        for (self.descriptors) |descriptor| {
            if (descriptor) |value| _ = system.close(value);
        }
        for (self.listeners) |listener| {
            if (listener.udp) |descriptor| _ = system.close(descriptor);
            if (listener.tcp) |descriptor| _ = system.close(descriptor);
        }
    }

    pub fn stop(self: *Runtime) Error!void {
        std.debug.assert(self.state == .running);
        self.state = .stopping;
        try self.proctor.stop();
        // No asynchronous socket I/O survives EV_DELETE. Pending datagrams can be discarded.
        for (&self.responses) |*response| response.listener = null;
    }

    pub fn step(self: *Runtime) Error!bool {
        if (self.state == .stopping) {
            std.debug.assert(!self.proctor.pending());
            return false;
        }
        const slot = (try self.proctor.next()) orelse return true;
        if (slot < 16) {
            try self.datagramReady(@intCast(slot));
            try self.receive(@intCast(slot));
        } else if (slot < timer_slot) {
            try self.accepted(@intCast(slot - 16));
        } else if (slot == timer_slot) {
            self.pipeline.reload(self.io, try now());
            try self.resumeAccepts();
            try self.proctor.arm(timer_slot, timer_slot, system.EVFILT.TIMER);
        } else if (slot < send_start) {
            try self.clientReady(@intCast(slot - client_start));
        } else {
            try self.sendReady(@intCast(slot - send_start));
        }
        return true;
    }

    fn receive(self: *Runtime, index: u16) Error!void {
        try self.proctor.arm(index, @intCast(self.listeners[index].udp.?), system.EVFILT.READ);
    }

    fn accept(self: *Runtime, index: u16) Error!void {
        try self.proctor.arm(
            16 + @as(u32, index),
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
        for (&self.responses) |*response| {
            if (response.listener != null) continue;
            const answer = self.pipeline.answer(
                self.input[0..@intCast(count)],
                &response.output,
                .{ .udp = family },
                try now(),
            ) catch return;
            const value = answer orelse return;
            response.address = source;
            response.address_length = message.namelen;
            response.length = @intCast(value.bytes.len);
            response.listener = listener;
            self.sendResponse(response);
            if (response.listener != null) try self.armSend(listener);
            return;
        }
        // Pool exhaustion drops only this datagram, with no overflow storage.
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
            self.sendResponse(response);
            if (response.listener != null) {
                try self.armSend(listener);
                return;
            }
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
            if (self.proctor.registrations[16 + index] != null) continue;
            try self.accept(@intCast(index));
        }
    }

    fn accepted(self: *Runtime, listener: u16) Error!void {
        const index = self.freeClient() orelse return;
        const descriptor = system.accept(self.listeners[listener].tcp.?, null, null);
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
        self.clients[index].reset();
        try self.armClient(index);
        if (self.freeClient() != null) try self.accept(listener);
    }

    fn armClient(self: *Runtime, index: u16) Error!void {
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
            .response => client.sent(@intCast(count)) catch return self.closeClient(index),
            .prefix, .body => {
                const query = client.received(@intCast(count)) catch
                    return self.closeClient(index);
                if (query) |bytes| {
                    const answer = self.pipeline.answer(
                        bytes,
                        client.output[2..],
                        .tcp,
                        try now(),
                    ) catch return self.closeClient(index);
                    const value = answer orelse return self.closeClient(index);
                    client.respond(value.bytes.len);
                }
            },
        }
        try self.armClient(index);
    }

    fn closeClient(self: *Runtime, index: u16) Error!void {
        // Called only after consuming the one-shot event. No queued event refers to this fd.
        std.debug.assert(self.proctor.registrations[client_start + @as(u32, index)] == null);
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
