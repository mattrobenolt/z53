//! Linux 7.2 is a contract, not a capability negotiation.
const std = @import("std");
pub const linux = std.os.linux;
const Ring = linux.IoUring;
const ownership = @import("ownership.zig");
pub const Ownership = ownership.Ownership;
pub const operations_max = 225;
pub const buffers_max = 64;
pub const buffer_bytes = 65535 + 16 + @sizeOf(linux.sockaddr.storage);
pub const cancel_bit: u64 = 1 << 63;
pub const Error = error{
    SetupFailed,
    SubmissionFailed,
    CompletionFailed,
    RegistrationFailed,
    InvalidCompletion,
    GenerationExhausted,
};

pub const Proctor = struct {
    ring: Ring,
    ownership: [operations_max]Ownership = @splat(.{}),
    buffers: [buffers_max][buffer_bytes]u8,
    provided: *align(std.heap.page_size_min) linux.io_uring_buf_ring,

    pub fn init(self: *Proctor) Error!void {
        self.ownership = @splat(.{});
        const flags = linux.IORING_SETUP_SINGLE_ISSUER | linux.IORING_SETUP_DEFER_TASKRUN;
        self.ring = Ring.init(256, flags) catch |err| {
            std.debug.print("z53: io_uring setup: {s}\n", .{@errorName(err)});
            return error.SetupFailed;
        };
        errdefer self.ring.deinit();
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

    /// Cancel synchronously before any kernel-visible memory is destroyed, including on errors.
    pub fn deinit(self: *Proctor) void {
        var cancellation = std.mem.zeroes(linux.io_uring_sync_cancel_reg);
        cancellation.flags = linux.IORING_ASYNC_CANCEL_ANY | linux.IORING_ASYNC_CANCEL_ALL;
        cancellation.timeout = .{ .sec = -1, .nsec = -1 };
        // Submit queued work first so cancellation covers every published SQE.
        _ = self.ring.submit() catch {
            std.debug.print("z53: io_uring teardown submission failed\n", .{});
            std.process.exit(1);
        };
        const result = linux.io_uring_register(
            self.ring.fd,
            .REGISTER_SYNC_CANCEL,
            &cancellation,
            1,
        );
        switch (linux.errno(result)) {
            .SUCCESS, .NOENT => {},
            else => {
                // Never free storage which the kernel could still access.
                std.debug.print("z53: io_uring teardown failed\n", .{});
                std.process.exit(1);
            },
        }
        // Ring destruction defers file release. Unregister synchronously so listeners
        // and direct accepts (including unread CQEs) release their socket references now.
        self.ring.unregister_files() catch |err| switch (err) {
            error.FilesNotRegistered => {}, // Startup may fail before table registration.
            else => {
                std.debug.print("z53: io_uring file teardown failed\n", .{});
                std.process.exit(1);
            },
        };
        Ring.free_buf_ring(self.ring.fd, self.provided, buffers_max, 0);
        self.ring.deinit();
        self.* = undefined;
    }

    pub fn registerClients(self: *Proctor) Error!void {
        // #1: pinned std passes sizeof(range), but this opcode requires nr_args=0.
        const range: linux.io_uring_file_index_range = .{ .off = 32, .len = 128, .resv = 0 };
        const result = linux.io_uring_register(self.ring.fd, .REGISTER_FILE_ALLOC_RANGE, &range, 0);
        if (linux.errno(result) != .SUCCESS) return error.RegistrationFailed;
    }

    pub fn recycle(self: *Proctor, index: u16) void {
        std.debug.assert(index < buffers_max);
        Ring.buf_ring_add(self.provided, &self.buffers[index], index, buffers_max - 1, 0);
        Ring.buf_ring_advance(self.provided, 1);
    }

    pub fn arm(self: *Proctor, index: u32) Error!u64 {
        std.debug.assert(index < operations_max);
        return self.ownership[index].arm(index);
    }

    pub fn next(self: *Proctor) Error!linux.io_uring_cqe {
        _ = self.ring.submit() catch return error.SubmissionFailed;
        const completion = self.ring.copy_cqe() catch return error.CompletionFailed;
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
            const token = owner.token(@intCast(index));
            _ = self.ring.cancel(token | cancel_bit, token, 0) catch return error.SubmissionFailed;
            owner.cancel();
        }
    }

    pub fn pending(self: *const Proctor) bool {
        for (&self.ownership) |*owner| {
            if (owner.state != .idle) return true;
        }
        return false;
    }
};
