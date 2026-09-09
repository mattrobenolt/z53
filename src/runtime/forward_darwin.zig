//! One-shot readiness and a nearest-deadline nanosecond timer own upstream sockets.
const std = @import("std");
const system = std.c;
const posix = std.posix;
const builtin = @import("builtin");

const runtime = @import("../runtime_darwin.zig");
const forward = @import("forward.zig");

pub const operation_start = runtime.upstream_start;
pub const timer_slot = operation_start + forward.sessions_max;

const Operation = struct {
    descriptor: ?system.fd_t = null,
    address: runtime.address.Address,
    peer: struct { endpoint: u16, generation: u31 },
};

const ConnectResult = enum { success, transport_failure, local_resource, cancelled };
const ConnectError = union(enum) {
    socket: system.E,
    syscall: system.E,
};

pub const Driver = struct {
    operations: [forward.sessions_max]Operation,
    timer_deadline_ns: ?u64,
    // Test-only override of the SO_ERROR result for one connect completion.
    test_connect_error: if (builtin.is_test) ?ConnectError else void,

    pub fn init(self: *Driver) void {
        for (&self.operations) |*operation| operation.descriptor = null;
        self.timer_deadline_ns = null;
        if (builtin.is_test) self.test_connect_error = null;
    }

    /// The caller removes kqueue interests before it releases descriptors.
    pub fn deinit(self: *Driver) void {
        for (&self.operations) |*operation| {
            if (operation.descriptor) |descriptor| _ = system.close(descriptor);
            operation.descriptor = null;
        }
        self.* = undefined;
    }

    pub fn drive(self: *Driver, service: *runtime.Runtime) runtime.Error!void {
        // Synchronous refusal can advance at most sixteen configured entries per transaction.
        for (0..16) |_| {
            for (&service.forward.transactions, 0..) |*transaction, index| {
                if (transaction.state != .ready) continue;
                try self.start(service, @intCast(index), service.tick_ns);
            }
        }
        // The final synchronous failure can exhaust the last entry without another socket event.
        for (&service.forward.transactions, 0..) |*transaction, index| {
            if (transaction.state == .ready)
                _ = service.forward.select(@intCast(index), service.tick_ns);
        }
        try service.deliverForwards();
        for (0..forward.probes_max) |_| {
            const now_ns = service.tick_ns;
            const index = service.forward.probe(now_ns) orelse break;
            try self.start(service, index, now_ns);
        }
        try service.deliverForwards();
        try self.timer(service);
    }

    fn start(self: *Driver, service: *runtime.Runtime, index: u16, now_ns: u64) runtime.Error!void {
        const selected = service.forward.select(index, now_ns) orelse return;
        const session = &service.forward.sessions[selected.session];
        service.forward.prepare(selected.session, &service.pipeline) catch {
            service.forward.localCompletion(
                selected.session,
                if (selected.action == .connect) .immediate else .close,
                now_ns,
            );
            if (selected.action != .connect) try self.close(service, selected.session, .retire);
            return;
        };
        switch (selected.action) {
            .connect => try self.connect(service, selected.session),
            .reuse => {
                session.state = .writing;
                if (session.transport == .tls) {
                    try self.pumpTls(service, selected.session);
                } else try self.arm(service, selected.session);
            },
            .replace => {
                try self.close(service, selected.session, .replace);
                try self.connect(service, selected.session);
            },
        }
    }

    fn connect(self: *Driver, service: *runtime.Runtime, index: u16) runtime.Error!void {
        const operation = &self.operations[index];
        const session = &service.forward.sessions[index];
        operation.address.fromIp(&service.forward.endpoints[session.endpoint]);
        const kind: u32 = if (session.transport == .udp) system.SOCK.DGRAM else system.SOCK.STREAM;
        const descriptor = system.socket(operation.address.storage.family, kind, 0);
        if (descriptor < 0) return self.localFailure(service, index);
        operation.descriptor = descriptor;
        runtime.address.prepare(descriptor) catch {
            _ = system.close(descriptor);
            operation.descriptor = null;
            return self.localFailure(service, index);
        };
        if (session.generation == std.math.maxInt(u31)) return error.GenerationExhausted;
        session.generation += 1;
        operation.peer = .{ .endpoint = session.endpoint, .generation = session.generation };
        session.state = .connecting;
        const result = system.connect(
            descriptor,
            @ptrCast(&operation.address.storage),
            operation.address.length,
        );
        if (result < 0) {
            switch (posix.errno(result)) {
                .INPROGRESS, .INTR => {},
                .CANCELED => return self.abortLocal(service, index),
                .MFILE, .NFILE, .NOBUFS, .NOMEM => return self.abortLocal(service, index),
                else => return self.close(service, index, .retry),
            }
        }
        try self.arm(service, index);
    }

    fn localFailure(self: *Driver, service: *runtime.Runtime, index: u16) runtime.Error!void {
        _ = self;
        service.forward.failed(index, .local_resource);
        const session = &service.forward.sessions[index];
        service.forward.localCompletion(index, .immediate, service.tick_ns);
        session.state = .vacant;
    }

    fn arm(self: *Driver, service: *runtime.Runtime, index: u16) runtime.Error!void {
        const session = &service.forward.sessions[index];
        if (service.tick_ns >= session.deadline_ns) return self.close(service, index, .retry);
        const filter: i16 = switch (session.state) {
            .connecting, .writing, .tls_write => system.EVFILT.WRITE,
            .read_prefix, .read_body, .read_datagram, .tls_read => system.EVFILT.READ,
            else => unreachable,
        };
        try service.proctor.arm(
            operation_start + @as(u32, index),
            @intCast(self.operations[index].descriptor.?),
            filter,
        );
    }

    pub fn ready(self: *Driver, service: *runtime.Runtime, index: u16) runtime.Error!void {
        const session = &service.forward.sessions[index];
        const descriptor = self.operations[index].descriptor.?;
        const now_ns = service.tick_ns;
        if (now_ns >= session.deadline_ns) return self.close(service, index, .retry);
        if (session.state == .connecting) {
            switch (self.connected(descriptor)) {
                .transport_failure => return self.close(service, index, .retry),
                .local_resource, .cancelled => return self.abortLocal(service, index),
                .success => {
                    service.forward.connected(index) catch |err|
                        return self.tlsFailed(service, index, err);
                    if (session.transport == .tls) return self.pumpTls(service, index);
                    return self.arm(service, index);
                },
            }
        }
        if (session.transport == .tls) return self.readyTls(service, index);
        const count = switch (session.state) {
            .writing => system.send(
                descriptor,
                session.output[session.offset..].ptr,
                session.length - session.offset,
                0,
            ),
            .read_prefix, .read_body, .read_datagram => system.recv(
                descriptor,
                session.input[session.offset..].ptr,
                session.length - session.offset,
                0,
            ),
            else => return error.InvalidCompletion,
        };
        if (count < 0) {
            switch (posix.errno(count)) {
                .AGAIN, .INTR => return self.arm(service, index),
                .CANCELED => return self.abortLocal(service, index),
                .MFILE, .NFILE, .NOBUFS, .NOMEM => return self.abortLocal(service, index),
                else => return self.close(service, index, .retry),
            }
        }
        if (session.state == .writing) {
            if (service.forward.sent(index, @intCast(count), service.tick_ns) == .failed)
                return self.close(service, index, .retry);
        } else switch (session.received(@intCast(count))) {
            .failed => return self.close(service, index, .retry),
            .progress => {},
            .frame => {
                const peer = self.operations[index].peer;
                if (service.forward.admitted(index, .{
                    .endpoint = peer.endpoint,
                    .generation = peer.generation,
                }, &service.pipeline)) {
                    service.forward.accepted(index, now_ns);
                    return;
                }
                session.startRead();
            },
        }
        try self.arm(service, index);
    }

    fn readyTls(self: *Driver, service: *runtime.Runtime, index: u16) runtime.Error!void {
        const session = &service.forward.sessions[index];
        const descriptor = self.operations[index].descriptor.?;
        const count = if (session.state == .tls_write) send: {
            const bytes = session.tls.pending();
            break :send system.send(descriptor, bytes.ptr, bytes.len, 0);
        } else receive: {
            const bytes = session.tls.writable();
            break :receive system.recv(descriptor, bytes.ptr, bytes.len, 0);
        };
        if (count < 0) {
            return switch (posix.errno(count)) {
                .AGAIN, .INTR => self.arm(service, index),
                .CANCELED => self.abortLocal(service, index),
                .MFILE, .NFILE, .NOBUFS, .NOMEM => self.abortLocal(service, index),
                else => self.close(service, index, .retry),
            };
        }
        const result = if (session.state == .tls_write)
            session.tls.sent(@intCast(count))
        else
            session.tls.received(@intCast(count));
        result catch |err| return self.tlsFailed(service, index, err);
        try self.pumpTls(service, index);
    }

    fn pumpTls(self: *Driver, service: *runtime.Runtime, index: u16) runtime.Error!void {
        service.forward.pumpTls(index, service.tick_ns, &service.pipeline) catch |err|
            return self.tlsFailed(service, index, err);
        if (service.forward.sessions[index].state != .idle) try self.arm(service, index);
    }

    fn tlsFailed(
        self: *Driver,
        service: *runtime.Runtime,
        index: u16,
        err: forward.tls.Error,
    ) runtime.Error!void {
        const session = &service.forward.sessions[index];
        session.failure_reason = if (session.tls.failure_reason) |cause|
            .{ .handshake = cause }
        else
            .{ .tls_io = err };
        try switch (err) {
            error.LocalFailure => self.abortLocal(service, index),
            error.TransportFailure => self.close(service, index, .retry),
        };
    }

    fn abortLocal(self: *Driver, service: *runtime.Runtime, index: u16) runtime.Error!void {
        service.forward.failed(index, service.forward.sessions[index].failure_reason);
        service.forward.localCompletion(index, .close, service.tick_ns);
        try self.close(service, index, .retire);
    }

    fn close(
        self: *Driver,
        service: *runtime.Runtime,
        index: u16,
        disposition: @FieldType(forward.Session, "disposition"),
    ) runtime.Error!void {
        if (disposition == .retry) {
            const session = &service.forward.sessions[index];
            const now_ns = service.tick_ns;
            var reason = session.failure_reason;
            if (reason == .transport_failure) {
                if (now_ns >= session.deadline_ns) reason = .timeout;
            }
            service.forward.failed(index, reason);
        }
        try service.proctor.remove(operation_start + @as(u32, index));
        _ = system.close(self.operations[index].descriptor.?);
        self.operations[index].descriptor = null;
        service.forward.sessions[index].state = .cancelling;
        service.forward.sessions[index].disposition = disposition;
        service.forward.closed(index, service.tick_ns);
    }

    pub fn expired(self: *Driver, service: *runtime.Runtime) runtime.Error!void {
        self.timer_deadline_ns = null;
        const now_ns = service.tick_ns;
        for (&service.forward.sessions, 0..) |*session, index| {
            switch (session.state) {
                .vacant, .cancelling => continue,
                else => {},
            }
            if (now_ns < session.deadline_ns) continue;
            try self.close(
                service,
                @intCast(index),
                if (session.state == .idle) .retire else .retry,
            );
        }
    }

    fn timer(self: *Driver, service: *runtime.Runtime) runtime.Error!void {
        var nearest = service.forward.probeDeadline();
        for (&service.forward.sessions) |*session| {
            switch (session.state) {
                .vacant, .cancelling => continue,
                else => {},
            }
            nearest = @min(nearest orelse session.deadline_ns, session.deadline_ns);
        }
        if (nearest == self.timer_deadline_ns) return;
        self.timer_deadline_ns = nearest;
        if (nearest) |deadline_ns| {
            // A relative kernel timer must exclude time spent inside this tick.
            try service.proctor.deadline(timer_slot, deadline_ns -| try runtime.nowNs());
        } else try service.proctor.remove(timer_slot);
    }

    fn connected(self: *Driver, descriptor: system.fd_t) ConnectResult {
        return switch (self.connectError(descriptor)) {
            .socket => |failure| classifyConnect(failure),
            .syscall => |failure| switch (classifyConnect(failure)) {
                .local_resource => .local_resource,
                .cancelled => .cancelled,
                else => .transport_failure,
            },
        };
    }

    fn connectError(self: *Driver, descriptor: system.fd_t) ConnectError {
        if (builtin.is_test) {
            if (self.test_connect_error) |failure| {
                self.test_connect_error = null;
                return failure;
            }
        }
        var failure: c_int = 0;
        var length: system.socklen_t = @sizeOf(c_int);
        const result = system.getsockopt(
            descriptor,
            system.SOL.SOCKET,
            system.SO.ERROR,
            &failure,
            &length,
        );
        if (result < 0) return .{ .syscall = posix.errno(result) };
        if (length != @sizeOf(c_int)) return .{ .syscall = .INVAL };
        return .{ .socket = @enumFromInt(failure) };
    }
};

fn classifyConnect(failure: system.E) ConnectResult {
    return switch (failure) {
        .SUCCESS => .success,
        .CANCELED => .cancelled,
        .MFILE, .NFILE, .NOBUFS, .NOMEM => .local_resource,
        else => .transport_failure,
    };
}
