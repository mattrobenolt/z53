//! One-shot readiness registrations. The kernel never borrows query buffers.
const std = @import("std");
const system = std.c;
pub const Ownership = @import("ownership.zig").Ownership;
pub const operations_max = 177;
pub const buffers_max = 64;
pub const Error = error{
    SetupFailed,
    RegistrationFailed,
    CompletionFailed,
    InvalidCompletion,
    GenerationExhausted,
};
const Registration = struct { ident: usize, filter: i16 };

pub const Proctor = struct {
    descriptor: system.fd_t,
    ownership: [operations_max]Ownership = @splat(.{}),
    registrations: [operations_max]?Registration = @splat(null),

    pub fn init(self: *Proctor) Error!void {
        self.ownership = @splat(.{});
        self.registrations = @splat(null);
        self.descriptor = system.kqueue();
        if (self.descriptor < 0) return error.SetupFailed;
        errdefer _ = system.close(self.descriptor);
        if (system.fcntl(self.descriptor, system.F.SETFD, @as(c_int, system.FD_CLOEXEC)) < 0)
            return error.SetupFailed;
    }

    /// Closing kqueue synchronously removes all readiness interests; no target I/O is pending.
    pub fn deinit(self: *Proctor) void {
        _ = system.close(self.descriptor);
        self.* = undefined;
    }

    pub fn arm(self: *Proctor, index: u32, ident: usize, filter: i16) Error!void {
        std.debug.assert(index < operations_max);
        std.debug.assert(self.registrations[index] == null);
        const token = try self.ownership[index].arm(index);
        errdefer self.ownership[index].complete(token, .terminal) catch unreachable;
        const change: system.Kevent = .{
            .ident = ident,
            .filter = filter,
            .flags = system.EV.ADD | system.EV.ONESHOT,
            .fflags = if (filter == system.EVFILT.TIMER) system.NOTE.SECONDS else 0,
            .data = if (filter == system.EVFILT.TIMER) 1 else 0,
            .udata = token,
        };
        if (system.kevent(self.descriptor, @ptrCast(&change), 1, &.{}, 0, null) < 0)
            return error.RegistrationFailed;
        self.registrations[index] = .{ .ident = ident, .filter = filter };
    }

    /// Fetch only one event: no userspace batch can outlive descriptor close or slot reuse.
    pub fn next(self: *Proctor) Error!?u32 {
        var event: system.Kevent = undefined;
        const count = system.kevent(self.descriptor, &.{}, 0, @ptrCast(&event), 1, null);
        if (count < 0) {
            if (std.posix.errno(count) == .INTR) return null;
            return error.CompletionFailed;
        }
        if (count != 1) return error.InvalidCompletion;
        if (event.flags & system.EV.ERROR != 0) return error.CompletionFailed;
        const index: u32 = @truncate(event.udata);
        if (index >= operations_max) return error.InvalidCompletion;
        const registration = self.registrations[index] orelse return error.InvalidCompletion;
        if (registration.ident != event.ident) return error.InvalidCompletion;
        if (registration.filter != event.filter) return error.InvalidCompletion;
        try self.ownership[index].complete(event.udata, .terminal);
        self.registrations[index] = null;
        // EOF is readiness too: recv drains buffered bytes before returning zero.
        return index;
    }

    pub fn remove(self: *Proctor, index: u32) Error!void {
        std.debug.assert(index < operations_max);
        const registration = self.registrations[index] orelse return;
        const change: system.Kevent = .{
            .ident = registration.ident,
            .filter = registration.filter,
            .flags = system.EV.DELETE,
            .fflags = 0,
            .data = 0,
            .udata = 0,
        };
        if (system.kevent(self.descriptor, @ptrCast(&change), 1, &.{}, 0, null) < 0)
            return error.RegistrationFailed;
        const owner = &self.ownership[index];
        try owner.complete(owner.token(index), .terminal);
        self.registrations[index] = null;
    }

    /// EV_DELETE is the cancellation barrier, unlike io_uring's two completion barrier.
    pub fn stop(self: *Proctor) Error!void {
        for (0..operations_max) |index| try self.remove(@intCast(index));
    }

    pub fn pending(self: *const Proctor) bool {
        for (self.registrations) |registration| {
            if (registration != null) return true;
        }
        return false;
    }
};
