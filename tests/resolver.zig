// SPEC §9.1: collect the synthetic, hosts, reload, and rotation unit tests.
test {
    _ = @import("resolver/synthetic.zig");
    _ = @import("resolver/hosts.zig");
    _ = @import("resolver/reload.zig");
    _ = @import("resolver/rotation.zig");
    _ = @import("resolver/cache.zig");
    _ = @import("resolver/cache_errors.zig");
    _ = @import("resolver/cache_boundaries.zig");
    _ = @import("resolver/cache_rcode.zig");
    _ = @import("resolver/cache_dname.zig");
}
