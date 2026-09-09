//! Linux 7.0.0 is a contract, not a capability negotiation.
const std = @import("std");
pub const linux = std.os.linux;
const Ring = linux.IoUring;
const assert = std.debug.assert;
const posix = std.posix;
const print = std.debug.print;
const page_size_max = std.heap.page_size_max;
const page_size_min = std.heap.page_size_min;
const alignForward = std.mem.alignForward;
const builtin = @import("builtin");

const wire = @import("../wire.zig");
const config = @import("../config.zig");
const tcp = @import("tcp.zig");
const ownership = @import("ownership.zig");
pub const Ownership = ownership.Ownership;

pub const ring_entries = 512;
pub const client_file_start = 2 * config.listeners_max;
pub const operations_max = 290;
pub const mapping_bytes_max = 256 * 1024;
pub const buffers_max = 64;
pub const buffer_bytes = wire.message_bytes_max +
    @sizeOf(linux.io_uring_recvmsg_out) + @sizeOf(linux.sockaddr.storage);
pub const cancel_bit: u64 = 1 << 63;

pub const Error = error{
    SetupFailed,
    SubmissionFailed,
    CompletionFailed,
    RegistrationFailed,
    InvalidCompletion,
    GenerationExhausted,
};

// The external test record survives Runtime destruction. Production retains no slot.
pub const TeardownObserver = struct {
    context: *anyopaque,
    cancellation_result: ?usize = null,
    submitted: *const fn (*anyopaque, *const linux.io_uring_sqe) void,
    completed: *const fn (*anyopaque, *const linux.io_uring_cqe) void,
    observe: *const fn (*anyopaque) void,
};

pub const Proctor = struct {
    ring: Ring,
    teardown_observer: if (builtin.is_test) ?*TeardownObserver else void =
        if (builtin.is_test) null else {},
    ownership: [operations_max]Ownership = @splat(.{}),
    buffers: [buffers_max][buffer_bytes]u8,
    provided: *align(page_size_min) linux.io_uring_buf_ring,

    pub fn init(self: *Proctor) Error!void {
        if (builtin.is_test) self.teardown_observer = null;
        self.ownership = @splat(.{});
        const flags = linux.IORING_SETUP_SINGLE_ISSUER | linux.IORING_SETUP_DEFER_TASKRUN;
        self.ring = Ring.init(ring_entries, flags) catch |err| {
            print("z53: io_uring setup: {s}\n", .{@errorName(err)});
            return error.SetupFailed;
        };
        errdefer self.ring.deinit();
        const mapping_bytes = alignForward(usize, self.ring.sq.mmap.len, page_size_max) +
            alignForward(usize, self.ring.sq.mmap_sqes.len, page_size_max) +
            alignForward(usize, buffers_max * @sizeOf(linux.io_uring_buf), page_size_max);
        if (mapping_bytes > mapping_bytes_max) return error.SetupFailed;
        // Non-incremental rings have one explicit ownership transfer per datagram.
        // The std helper's retry branch only applies to incremental rings.
        self.provided = Ring.setup_buf_ring(self.ring.fd, buffers_max, 0, .{ .inc = false }) catch
            return error.RegistrationFailed;
        Ring.buf_ring_init(self.provided);
        for (&self.buffers, 0..) |*buffer, index| {
            Ring.buf_ring_add(
                self.provided,
                buffer,
                @intCast(index),
                buffers_max - 1,
                @intCast(index),
            );
        }
        Ring.buf_ring_advance(self.provided, buffers_max);
    }

    /// Retain kernel-visible storage until request retirement and both resource barriers succeed.
    pub fn deinit(self: *Proctor) void {
        self.teardown() catch |err| {
            print("z53: io_uring teardown: {s}\n", .{@errorName(err)});
            // Process exit does not unwind Runtime or Pipeline storage.
            std.process.exit(1);
        };
        const metadata: [*]align(page_size_min) u8 = @ptrCast(self.provided);
        posix.munmap(metadata[0 .. buffers_max * @sizeOf(linux.io_uring_buf)]);
        self.ring.deinit();
        self.* = undefined;
    }

    fn teardown(self: *Proctor) TeardownError!void {
        const deadline_ns = std.math.add(u64, try teardownNow(), 5 * std.time.ns_per_s) catch
            return error.TeardownClockFailed;
        try self.teardownSubmit(deadline_ns);
        var cancellation = std.mem.zeroes(linux.io_uring_sync_cancel_reg);
        cancellation.flags = linux.IORING_ASYNC_CANCEL_ANY | linux.IORING_ASYNC_CANCEL_ALL;
        cancellation.timeout = teardownTimespec(try teardownRemaining(deadline_ns));
        const result = linux.io_uring_register(
            self.ring.fd,
            .REGISTER_SYNC_CANCEL,
            &cancellation,
            1,
        );
        if (builtin.is_test) {
            if (self.teardown_observer) |observer| observer.cancellation_result = result;
        }
        switch (linux.errno(result)) {
            .SUCCESS, .NOENT => {},
            else => return error.TeardownCancellationFailed,
        }
        _ = try teardownRemaining(deadline_ns);
        // A separate submission ends any older link chain before this standalone marker.
        const marker = self.ring.nop(teardown_token) catch return error.TeardownSubmissionFailed;
        marker.flags = linux.IOSQE_IO_DRAIN;
        marker.rw_flags = 0;
        if (builtin.is_test) {
            if (self.teardown_observer) |observer| observer.submitted(observer.context, marker);
        }
        try self.teardownSubmit(deadline_ns);
        // No later SQE is prepared or submitted, including timeout SQEs.
        try self.teardownDrain(deadline_ns);
        _ = try teardownRemaining(deadline_ns);
        self.ring.unregister_files() catch |err| switch (err) {
            error.FilesNotRegistered => {}, // Startup can fail before table registration.
            else => return error.TeardownFilesFailed,
        };
        // The snapshot must precede provided-buffer and completion mapping destruction.
        if (builtin.is_test) {
            if (self.teardown_observer) |observer| observer.observe(observer.context);
        }
        _ = try teardownRemaining(deadline_ns);
        const registration = std.mem.zeroes(linux.io_uring_buf_reg);
        const unregistered = linux.io_uring_register(
            self.ring.fd,
            .UNREGISTER_PBUF_RING,
            &registration,
            1,
        );
        if (linux.errno(unregistered) != .SUCCESS) return error.TeardownBuffersFailed;
        _ = try teardownRemaining(deadline_ns);
    }

    fn teardownSubmit(self: *Proctor, deadline_ns: u64) TeardownError!void {
        // Each successful enter consumes at least one of the queued SQEs.
        for (0..ring_entries) |_| {
            _ = try teardownRemaining(deadline_ns);
            try self.teardownDropped();
            const queued = self.ring.sq_ready();
            if (queued == 0) return;
            if (queued > ring_entries) return error.TeardownSubmissionFailed;
            const submitted = self.ring.submit() catch return error.TeardownSubmissionFailed;
            if (submitted == 0) return error.TeardownSubmissionFailed;
            if (submitted > queued) return error.TeardownSubmissionFailed;
            if (self.ring.sq_ready() != queued - submitted) return error.TeardownSubmissionFailed;
        }
        _ = try teardownRemaining(deadline_ns);
        try self.teardownDropped();
        if (self.ring.sq_ready() != 0) return error.TeardownSubmissionFailed;
    }

    fn teardownDrain(self: *Proctor, deadline_ns: u64) TeardownError!void {
        var consumed: u32 = 0;
        // At most one wait and one nonempty batch per CQE, plus the final marker batch.
        for (0..teardown_completions_max * 2 + 1) |_| {
            _ = try teardownRemaining(deadline_ns);
            try self.teardownDropped();
            const ready = self.ring.cq_ready();
            if (ready == 0) {
                try self.teardownWait(deadline_ns);
                continue;
            }
            if (ready > self.ring.cq.cqes.len) return error.TeardownCompletionFailed;
            var batch: [32]linux.io_uring_cqe = undefined;
            const count = @min(ready, batch.len);
            if (count > teardown_completions_max - consumed) return error.TeardownExhausted;
            // Copy published entries only. The std batch helper can enter without a deadline.
            for (batch[0..count], 0..) |*completion, index| {
                const slot = (self.ring.cq.head.* +% @as(u32, @intCast(index))) & self.ring.cq.mask;
                completion.* = self.ring.cq.cqes[slot];
            }
            self.ring.cq_advance(count);
            consumed += count;
            for (batch[0..count]) |*completion| {
                if (builtin.is_test) {
                    if (self.teardown_observer) |observer|
                        observer.completed(observer.context, completion);
                }
                if (completion.user_data != teardown_token) continue;
                if (completion.res != 0) return error.TeardownMarkerFailed;
                if (completion.flags != 0) return error.TeardownMarkerFailed;
                try self.teardownDropped();
                _ = try teardownRemaining(deadline_ns);
                return;
            }
            if (consumed == teardown_completions_max) return error.TeardownExhausted;
        }
        return error.TeardownExhausted;
    }

    fn teardownWait(self: *Proctor, deadline_ns: u64) TeardownError!void {
        _ = try teardownRemaining(deadline_ns);
        const deadline = teardownTimespec(deadline_ns);
        const argument: linux.io_uring_getevents_arg = .{
            .sigmask = 0,
            .sigmask_sz = 0,
            .pad = 0,
            .ts = @intFromPtr(&deadline),
        };
        // v7.2.3 UAPI defines ABS_TIMER at bit 5. Pinned std lacks this constant.
        const absolute_timer = 1 << 5;
        // The std wrapper fixes argsz to NSIG/8 instead of sizeof(getevents_arg).
        const result = linux.syscall6(
            .io_uring_enter,
            @intCast(self.ring.fd),
            0,
            1,
            linux.IORING_ENTER_GETEVENTS | linux.IORING_ENTER_EXT_ARG | absolute_timer,
            @intFromPtr(&argument),
            @sizeOf(linux.io_uring_getevents_arg),
        );
        switch (linux.errno(result)) {
            .SUCCESS => {},
            .TIME => return error.TeardownDeadline,
            else => return error.TeardownCompletionFailed,
        }
    }

    fn teardownDropped(self: *const Proctor) TeardownError!void {
        if (@atomicLoad(u32, self.ring.sq.dropped, .acquire) != 0)
            return error.TeardownSubmissionFailed;
        // NODROP overflow queues are lossless. This counter records actual dropped CQEs.
        if (@atomicLoad(u32, self.ring.cq.overflow, .acquire) != 0)
            return error.TeardownCompletionFailed;
    }

    pub fn registerClients(self: *Proctor) Error!void {
        // pinned std passes sizeof(range), but this opcode requires nr_args=0.
        const range: linux.io_uring_file_index_range = .{
            .off = client_file_start,
            .len = tcp.clients_max,
            .resv = 0,
        };
        const result = linux.io_uring_register(self.ring.fd, .REGISTER_FILE_ALLOC_RANGE, &range, 0);
        if (linux.errno(result) != .SUCCESS) return error.RegistrationFailed;
    }

    pub fn recycle(self: *Proctor, index: u16) void {
        assert(index < buffers_max);
        Ring.buf_ring_add(self.provided, &self.buffers[index], index, buffers_max - 1, 0);
        Ring.buf_ring_advance(self.provided, 1);
    }

    pub fn arm(self: *Proctor, index: u32) Error!u64 {
        assert(index < operations_max);
        return self.ownership[index].arm(index);
    }

    /// An interrupted enter returns no completion and leaves operation ownership unchanged.
    pub fn next(self: *Proctor) Error!?linux.io_uring_cqe {
        // The shared SQ head preserves unconsumed entries across an interrupted enter.
        _ = self.ring.submit() catch |err| switch (err) {
            error.SignalInterrupt => return null,
            else => return error.SubmissionFailed,
        };
        const completion = self.ring.copy_cqe() catch |err| switch (err) {
            error.SignalInterrupt => return null,
            else => return error.CompletionFailed,
        };
        const index: u32 = @truncate(completion.user_data);
        if (index >= operations_max) return error.InvalidCompletion;
        if (completion.user_data & cancel_bit != 0) {
            switch (completion.err()) {
                .SUCCESS, .NOENT, .ALREADY => {},
                else => return error.CompletionFailed,
            }
        }
        const kind: ownership.Completion = if (completion.user_data & cancel_bit != 0)
            .cancellation
        else if (completion.flags & linux.IORING_CQE_F_MORE != 0)
            .more
        else
            .terminal;
        try self.ownership[index].complete(completion.user_data, kind);
        return completion;
    }

    pub fn stop(self: *Proctor) Error!void {
        for (&self.ownership, 0..) |*owner, index| {
            if (owner.state != .active) continue;
            try self.reserve(1);
            const token = owner.token(@intCast(index));
            _ = self.ring.cancel(token | cancel_bit, token, 0) catch return error.SubmissionFailed;
            owner.cancel();
        }
    }

    /// Account for unpublished SQEs too, including work queued before stop.
    pub fn reserve(self: *Proctor, count: u32) Error!void {
        assert(count <= self.ring.sq.sqes.len);
        if (self.ring.sq_ready() + count > self.ring.sq.sqes.len) {
            _ = self.ring.submit() catch return error.SubmissionFailed;
        }
        if (self.ring.sq_ready() + count > self.ring.sq.sqes.len)
            return error.SubmissionFailed;
    }

    pub fn pending(self: *const Proctor) bool {
        for (&self.ownership) |*owner| {
            if (owner.state != .idle) return true;
        }
        return false;
    }
};

// low token bits cannot alias any normal or cancellation owner index.
const teardown_token: u64 = std.math.maxInt(u64);
// 1024 published + 290 terminals + 290 acknowledgements + 64 UDP shots + 256 accepts + marker.
const teardown_completions_max = 2048;
const TeardownError = error{
    TeardownClockFailed,
    TeardownDeadline,
    TeardownSubmissionFailed,
    TeardownCancellationFailed,
    TeardownCompletionFailed,
    TeardownMarkerFailed,
    TeardownExhausted,
    TeardownFilesFailed,
    TeardownBuffersFailed,
};

fn teardownNow() TeardownError!u64 {
    var timestamp: linux.timespec = undefined;
    if (linux.errno(linux.clock_gettime(.MONOTONIC, &timestamp)) != .SUCCESS)
        return error.TeardownClockFailed;
    if (timestamp.sec < 0) return error.TeardownClockFailed;
    if (timestamp.nsec < 0) return error.TeardownClockFailed;
    if (timestamp.nsec >= std.time.ns_per_s) return error.TeardownClockFailed;
    const seconds_ns = std.math.mul(u64, @intCast(timestamp.sec), std.time.ns_per_s) catch
        return error.TeardownClockFailed;
    return std.math.add(u64, seconds_ns, @intCast(timestamp.nsec)) catch error.TeardownClockFailed;
}

fn teardownRemaining(deadline_ns: u64) TeardownError!u64 {
    const now_ns = try teardownNow();
    if (now_ns >= deadline_ns) return error.TeardownDeadline;
    return deadline_ns - now_ns;
}

fn teardownTimespec(timestamp_ns: u64) linux.kernel_timespec {
    return .{
        .sec = @intCast(timestamp_ns / std.time.ns_per_s),
        .nsec = @intCast(timestamp_ns % std.time.ns_per_s),
    };
}
