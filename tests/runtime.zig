const std = @import("std");
const testing = std.testing;
const linux = std.os.linux;
const builtin = @import("builtin");

const runtime = @import("runtime");
const wire = runtime.pipeline.wire;

test {
    _ = @import("runtime_forward.zig");
    _ = @import("runtime_health.zig");
    _ = @import("runtime_log.zig");
    if (builtin.os.tag == .linux) {
        _ = @import("runtime_transport.zig");
        _ = @import("runtime_interrupt.zig");
    } else {
        _ = @import("runtime_darwin.zig");
    }
}

// SPEC §1: mandatory ring setup, provided buffers, and cancellation execute on Linux.
test "native ring setup registered files and cancellation" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const proctor = try testing.allocator.create(runtime.proctor.Proctor);
    defer testing.allocator.destroy(proctor);
    try proctor.init();
    defer proctor.deinit();
    try proctor.ring.register_files_sparse(160);
    var interval: linux.kernel_timespec = .{ .sec = 60, .nsec = 0 };
    const token = try proctor.arm(32);
    _ = try proctor.ring.timeout(token, &interval, 0, 0);
    _ = try proctor.ring.submit();
    try proctor.stop();
    var completions: u8 = 0;
    for (0..4) |_| {
        if (!proctor.pending()) break;
        if (try proctor.next() == null) continue;
        completions += 1;
        try testing.expect(completions <= 2);
    }
    try testing.expect(!proctor.pending());
    try testing.expectEqual(2, completions);
}

// SPEC §1: teardown also handles startup before the file table was registered.
test "native proctor teardown without registered files" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const proctor = try testing.allocator.create(runtime.proctor.Proctor);
    defer testing.allocator.destroy(proctor);
    try proctor.init();
    proctor.deinit();
}

// SPEC §1: actual io_uring_setup failure is a startup error, with no probe or fallback.
test "native setup failure under descriptor quota" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const proctor = try testing.allocator.create(runtime.proctor.Proctor);
    defer testing.allocator.destroy(proctor);
    var previous: linux.rlimit = undefined;
    try testing.expectEqual(.SUCCESS, linux.errno(linux.prlimit(0, .NOFILE, null, &previous)));
    const limited: linux.rlimit = .{ .cur = 0, .max = previous.max };
    try testing.expectEqual(.SUCCESS, linux.errno(linux.prlimit(0, .NOFILE, &limited, null)));
    defer {
        const restored = linux.prlimit(0, .NOFILE, &previous, null);
        testing.expectEqual(.SUCCESS, linux.errno(restored)) catch
            @panic("failed to restore descriptor quota");
    }
    try testing.expectError(error.SetupFailed, proctor.init());
}
