//! Compile-time transport selection. No runtime probing or blocking fallback.
const std = @import("std");
const runtime = @This();
const platform = switch (builtin.os.tag) {
    .linux => linux,
    .macos => darwin,
    else => @compileError("z53 supports Linux and macOS only"),
};
pub const Runtime = platform.Runtime;
pub const Error = platform.Error;
pub const now = platform.now;
pub const proctor = platform.proctor;
pub const address = platform.address;
pub const nowNs = platform.nowNs;

const builtin = @import("builtin");

const darwin = @import("runtime_darwin.zig");
const linux = @import("runtime_linux.zig");
pub const forward = @import("runtime/forward.zig");
pub const log = @import("runtime/log.zig");
pub const pipeline = @import("runtime/pipeline.zig");
pub const tcp = @import("runtime/tcp.zig");
pub const udp = @import("runtime/udp.zig");

comptime {
    if (builtin.is_test) _ = pipeline;
}

comptime {
    if (builtin.is_test) _ = RuntimeUnitTests;
}

const RuntimeUnitTests = struct {
    const testing = std.testing;
    const wire = runtime.pipeline.wire;

    // SPEC §1.3: the cap excludes cache entry arrays and packets, hosts tables, and configuration.
    test "runtime fixed storage budget" {
        const external = runtime.pipeline.zone_storage_bytes_max +
            if (builtin.os.tag == .linux) runtime.proctor.mapping_bytes_max else 0;
        try testing.expect(@sizeOf(runtime.Runtime) + external <= 40 * 1024 * 1024);
        try testing.expect(
            @sizeOf(runtime.forward.Forward) + @sizeOf(@FieldType(runtime.Runtime, "upstreams")) <=
                runtime.forward.storage_bytes_max,
        );
        try testing.expectEqual(128, runtime.tcp.clients_max);
        try testing.expectEqual(64, runtime.proctor.buffers_max);
        try testing.expectEqual(
            if (builtin.os.tag == .linux) 290 else 210,
            runtime.proctor.operations_max,
        );
    }
};
