//! #1: each linked pair retains both completions and both explicit cancellation barriers.
const std = @import("std");
const runtime = @import("../runtime_linux.zig");
const forward = @import("forward.zig");
const retired = forward.retired;
const linux = std.os.linux;
pub const operation_start = 225;
pub const timer_slot = 289;
pub const file_start = 160;
const Operation = struct {
    kind: enum { none, pair, close } = .none,
    result: ?i32 = null,
    timeout_result: ?i32 = null,
    timeout: linux.kernel_timespec,
    address: runtime.address.Address,
    peer: struct { endpoint: u16, generation: u31 },
};
pub const Driver = struct {
    operations: [forward.sessions_max]Operation,
    interval: linux.kernel_timespec,
    timer_deadline_ns: ?u64,

    pub fn init(self: *Driver) void {
        for (&self.operations) |*operation| operation.kind = .none;
        self.interval = .{ .sec = 0, .nsec = 1 };
        self.timer_deadline_ns = null;
    }

    pub fn drive(self: *Driver, service: *runtime.Runtime) runtime.Error!void {
        const now_ns = try runtime.nowNs();
        for (&service.forward.transactions, 0..) |*transaction, index| {
            if (transaction.state != .ready) continue;
            const selected = service.forward.select(@intCast(index), now_ns) orelse continue;
            const session = &service.forward.sessions[selected.session];
            service.forward.prepare(selected.session, &service.pipeline) catch {
                transaction.completion = .local_failure;
                transaction.state = .deliver;
                session.transaction = null;
                if (selected.action != .connect) try self.close(service, selected.session, .retire);
                continue;
            };
            switch (selected.action) {
                .connect => try self.connect(service, selected.session),
                .reuse => {
                    session.state = .writing;
                    if (session.transport == .tls) {
                        try self.pumpTls(service, selected.session);
                    } else try self.arm(service, selected.session);
                },
                .replace => try self.close(service, selected.session, .replace),
            }
        }
        try service.deliverForwards();
        try self.timer(service);
    }

    fn connect(self: *Driver, service: *runtime.Runtime, index: u16) runtime.Error!void {
        const session = &service.forward.sessions[index];
        const operation = &self.operations[index];
        operation.address.fromIp(&service.forward.endpoints[session.endpoint]);
        const kind: u32 = if (session.transport == .udp) linux.SOCK.DGRAM else linux.SOCK.STREAM;
        const result = linux.socket(
            operation.address.storage.family,
            kind | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK,
            0,
        );
        if (linux.errno(result) != .SUCCESS) {
            self.localFailure(service, index);
            return;
        }
        const descriptor: linux.fd_t = @intCast(result);
        defer _ = linux.close(descriptor);
        service.proctor.ring.register_files_update(
            file_start + @as(u32, index),
            &.{descriptor},
        ) catch {
            self.localFailure(service, index);
            return;
        };
        if (session.generation == std.math.maxInt(u31)) return error.GenerationExhausted;
        session.generation += 1;
        operation.peer = .{ .endpoint = session.endpoint, .generation = session.generation };
        session.state = .connecting;
        try self.arm(service, index);
    }

    fn localFailure(self: *Driver, service: *runtime.Runtime, index: u16) void {
        _ = self;
        service.forward.failed(index, "local_resource");
        const session = &service.forward.sessions[index];
        const transaction = &service.forward.transactions[session.transaction.?];
        transaction.completion = .local_failure;
        transaction.state = .deliver;
        session.transaction = null;
        session.state = .vacant;
    }

    fn arm(self: *Driver, service: *runtime.Runtime, index: u16) runtime.Error!void {
        const session = &service.forward.sessions[index];
        const now_ns = try runtime.nowNs();
        if (now_ns >= session.deadline_ns) return self.close(service, index, .retry);
        const operation = &self.operations[index];
        std.debug.assert(operation.kind == .none);
        try service.proctor.reserve(2);
        const slot = operation_start + @as(u32, index) * 2;
        const token = try service.proctor.arm(slot);
        const timeout_token = try service.proctor.arm(slot + 1);
        const descriptor: i32 = file_start + @as(i32, index);
        const entry = switch (session.state) {
            .connecting => service.proctor.ring.connect(
                token,
                descriptor,
                @ptrCast(&operation.address.storage),
                operation.address.length,
            ),
            .writing => service.proctor.ring.send(
                token,
                descriptor,
                session.output[session.offset..session.length],
                linux.MSG.NOSIGNAL,
            ),
            .tls_write => service.proctor.ring.send(
                token,
                descriptor,
                session.tls.pending(),
                linux.MSG.NOSIGNAL,
            ),
            .tls_read => service.proctor.ring.recv(
                token,
                descriptor,
                .{ .buffer = session.tls.writable() },
                0,
            ),
            .read_prefix, .read_body, .read_datagram => service.proctor.ring.recv(
                token,
                descriptor,
                .{ .buffer = session.input[session.offset..session.length] },
                0,
            ),
            else => unreachable,
        } catch return error.SubmissionFailed;
        entry.flags |= linux.IOSQE_FIXED_FILE | linux.IOSQE_IO_LINK;
        // An SQE can wait before submission. Absolute time prevents renewal of its budget.
        operation.timeout = .{
            .sec = @intCast(session.deadline_ns / std.time.ns_per_s),
            .nsec = @intCast(session.deadline_ns % std.time.ns_per_s),
        };
        _ = service.proctor.ring.link_timeout(
            timeout_token,
            &operation.timeout,
            linux.IORING_TIMEOUT_ABS,
        ) catch return error.SubmissionFailed;
        operation.kind = .pair;
        operation.result = null;
        operation.timeout_result = null;
    }

    pub fn completed(
        self: *Driver,
        service: *runtime.Runtime,
        completion: *const linux.io_uring_cqe,
    ) runtime.Error!void {
        const slot: u32 = @truncate(completion.user_data);
        const index: u16 = @intCast((slot - operation_start) / 2);
        const operation = &self.operations[index];
        if (completion.user_data & runtime.proctor.cancel_bit == 0) {
            if ((slot - operation_start) % 2 == 0) {
                operation.result = completion.res;
            } else operation.timeout_result = completion.res;
        }
        const first = operation_start + @as(u32, index) * 2;
        if (!retired(
            &service.proctor.ownership[first],
            &service.proctor.ownership[first + 1],
        )) return;
        if (service.state == .stopping) return;
        const kind = operation.kind;
        operation.kind = .none;
        if (kind == .close) {
            if (operation.result.? < 0) return error.TransportFailed;
            service.forward.closed(index);
            if (service.forward.sessions[index].disposition == .replace)
                try self.connect(service, index);
            return;
        }
        if (kind != .pair) return error.InvalidCompletion;
        const count = operation.result orelse return error.InvalidCompletion;
        const timeout_result = operation.timeout_result orelse return error.InvalidCompletion;
        if (timeout_result >= 0) return error.InvalidCompletion;
        switch (completionError(timeout_result)) {
            .CANCELED, .ALREADY, .NOENT => {},
            .TIME => {
                service.forward.sessions[index].failure_reason = "timeout";
                return self.close(service, index, .retry);
            },
            else => return error.InvalidCompletion,
        }
        if (count < 0) {
            service.forward.sessions[index].failure_reason = @tagName(completionError(count));
            switch (completionError(count)) {
                .MFILE, .NFILE, .NOBUFS, .NOMEM => return self.abortLocal(service, index),
                else => return self.close(service, index, .retry),
            }
        }
        try self.advance(service, index, count);
    }

    fn abortLocal(self: *Driver, service: *runtime.Runtime, index: u16) runtime.Error!void {
        service.forward.failed(index, service.forward.sessions[index].failure_reason);
        const session = &service.forward.sessions[index];
        const transaction = &service.forward.transactions[session.transaction.?];
        transaction.completion = .local_failure;
        transaction.state = .deliver;
        session.transaction = null;
        try self.close(service, index, .retire);
    }

    fn advance(
        self: *Driver,
        service: *runtime.Runtime,
        index: u16,
        count: i32,
    ) runtime.Error!void {
        const session = &service.forward.sessions[index];
        const now_ns = try runtime.nowNs();
        if (now_ns >= session.deadline_ns) return self.close(service, index, .retry);
        switch (session.state) {
            .connecting => {
                service.forward.connected(index) catch |err|
                    return self.tlsFailed(service, index, err);
                if (session.transport == .tls) return self.pumpTls(service, index);
            },
            .tls_read, .tls_write => {
                const result = if (session.state == .tls_read)
                    session.tls.received(count)
                else
                    session.tls.sent(count);
                result catch |err| return self.tlsFailed(service, index, err);
                return self.pumpTls(service, index);
            },
            .writing => {
                if (service.forward.sent(index, count, now_ns) == .failed)
                    return self.close(service, index, .retry);
            },
            .read_prefix, .read_body, .read_datagram => switch (session.received(count)) {
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
                    // Rejected frames consume the original response budget, never a new one.
                    session.startRead();
                },
            },
            else => return error.InvalidCompletion,
        }
        try self.arm(service, index);
    }

    fn pumpTls(self: *Driver, service: *runtime.Runtime, index: u16) runtime.Error!void {
        service.forward.pumpTls(index, try runtime.nowNs(), &service.pipeline) catch |err|
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
        session.failure_reason = session.tls.failure_reason orelse @errorName(err);
        switch (err) {
            error.LocalFailure => try self.abortLocal(service, index),
            error.TransportFailure => try self.close(service, index, .retry),
        }
    }

    fn close(
        self: *Driver,
        service: *runtime.Runtime,
        index: u16,
        disposition: @FieldType(forward.Session, "disposition"),
    ) runtime.Error!void {
        if (disposition == .retry) {
            const session = &service.forward.sessions[index];
            const now_ns = runtime.nowNs() catch 0;
            var reason = session.failure_reason;
            if (std.mem.eql(u8, reason, "transport_failure")) {
                if (now_ns >= session.deadline_ns) reason = "timeout";
            }
            service.forward.failed(index, reason);
        }
        const slot = operation_start + @as(u32, index) * 2;
        std.debug.assert(retired(
            &service.proctor.ownership[slot],
            &service.proctor.ownership[slot + 1],
        ));
        const operation = &self.operations[index];
        std.debug.assert(operation.kind == .none);
        try service.proctor.reserve(1);
        const token = try service.proctor.arm(slot);
        _ = service.proctor.ring.close_direct(token, file_start + @as(u32, index)) catch
            return error.SubmissionFailed;
        operation.kind = .close;
        operation.result = null;
        service.forward.sessions[index].state = .cancelling;
        service.forward.sessions[index].disposition = disposition;
    }

    pub fn expired(self: *Driver, service: *runtime.Runtime) runtime.Error!void {
        const now_ns = try runtime.nowNs();
        for (&service.forward.sessions, 0..) |*session, index| {
            if (session.state != .idle) continue;
            if (now_ns < session.deadline_ns) continue;
            try self.close(service, @intCast(index), .retire);
        }
    }

    fn timer(self: *Driver, service: *runtime.Runtime) runtime.Error!void {
        var nearest: ?u64 = null;
        for (&service.forward.sessions) |*session| {
            if (session.state != .idle) continue;
            nearest = @min(nearest orelse session.deadline_ns, session.deadline_ns);
        }
        const owner = &service.proctor.ownership[timer_slot];
        if (owner.state != .idle) {
            if (owner.state == .active) {
                if (nearest) |deadline_ns| {
                    if (deadline_ns < self.timer_deadline_ns.?) {
                        try service.proctor.reserve(1);
                        const token = owner.token(timer_slot);
                        _ = service.proctor.ring.cancel(
                            token | runtime.proctor.cancel_bit,
                            token,
                            0,
                        ) catch
                            return error.SubmissionFailed;
                        owner.cancel();
                    }
                }
            }
            return;
        }
        const deadline_ns = nearest orelse return;
        self.timer_deadline_ns = deadline_ns;
        self.interval = .{
            .sec = @intCast(deadline_ns / std.time.ns_per_s),
            .nsec = @intCast(deadline_ns % std.time.ns_per_s),
        };
        try service.proctor.reserve(1);
        const token = try service.proctor.arm(timer_slot);
        _ = service.proctor.ring.timeout(
            token,
            &self.interval,
            0,
            linux.IORING_TIMEOUT_ABS,
        ) catch return error.SubmissionFailed;
    }
};

fn completionError(result: i32) linux.E {
    std.debug.assert(result < 0);
    return @enumFromInt(-result);
}
