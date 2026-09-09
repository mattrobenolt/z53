const std = @import("std");
const runtime = @import("runtime");
const testing = std.testing;
const linux = std.os.linux;

const SignalSender = struct {
    process: linux.pid_t,
    thread: linux.pid_t,
    state: std.atomic.Value(enum(u8) { active, stopped }) = .init(.active),
    result: linux.E = .SUCCESS,

    fn run(self: *SignalSender) void {
        const interval: linux.timespec = .{ .sec = 0, .nsec = 20 * std.time.ns_per_ms };
        // Repeated delivery tolerates a signal between submission and the wait.
        for (0..100) |_| {
            self.result = linux.errno(linux.nanosleep(&interval, null));
            if (self.result != .SUCCESS) return;
            if (self.state.load(.acquire) == .stopped) return;
            self.result = linux.errno(linux.tgkill(self.process, self.thread, .USR2));
            if (self.result != .SUCCESS) return;
        }
    }

    fn handler(_: std.posix.SIG) callconv(.c) void {}
};

// SPEC §1.1: an interrupted wait retains the pending operation and its generation.
test "native interrupted completion wait retains ownership" {
    const proctor = try testing.allocator.create(runtime.proctor.Proctor);
    defer testing.allocator.destroy(proctor);
    try proctor.init();
    defer proctor.deinit();
    const action: std.posix.Sigaction = .{
        .handler = .{ .handler = SignalSender.handler },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    var previous: std.posix.Sigaction = undefined;
    std.posix.sigaction(.USR2, &action, &previous);
    defer std.posix.sigaction(.USR2, &previous, null);
    var selected = std.posix.sigemptyset();
    std.posix.sigaddset(&selected, .USR2);
    var previous_mask: std.posix.sigset_t = undefined;
    std.posix.sigprocmask(std.posix.SIG.UNBLOCK, &selected, &previous_mask);
    defer std.posix.sigprocmask(std.posix.SIG.SETMASK, &previous_mask, null);
    // The timeout bounds the test if no signal reaches the event thread.
    const interval: linux.kernel_timespec = .{ .sec = 3, .nsec = 0 };
    const token = try proctor.arm(32);
    _ = try proctor.ring.timeout(token, &interval, 0, 0);
    var sender: SignalSender = .{ .process = linux.getpid(), .thread = linux.gettid() };
    {
        const thread = try std.Thread.spawn(.{}, SignalSender.run, .{&sender});
        defer thread.join();
        defer sender.state.store(.stopped, .release);
        try testing.expectEqual(null, try proctor.next());
        try testing.expectEqual(.active, proctor.ownership[32].state);
        try testing.expectEqual(token, proctor.ownership[32].token(32));
        try testing.expectEqual(0, proctor.ring.sq_ready());
    }
    try testing.expectEqual(.SUCCESS, sender.result);
    try proctor.stop();
    for (0..4) |_| {
        if (!proctor.pending()) break;
        _ = try proctor.next();
    }
    try testing.expect(!proctor.pending());
    try testing.expectEqual(.idle, proctor.ownership[32].state);
}
