//! Compile-time transport selection. No runtime probing or blocking fallback.
const builtin = @import("builtin");
const linux = @import("runtime_linux.zig");
const darwin = @import("runtime_darwin.zig");
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
pub const tcp = @import("runtime/tcp.zig");
pub const udp = @import("runtime/udp.zig");
pub const pipeline = @import("runtime/pipeline.zig");
