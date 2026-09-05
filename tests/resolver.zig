// SPEC §9.1: collect the synthetic, hosts, reload, and rotation unit tests.
test {
    _ = @import("resolver/synthetic.zig");
    _ = @import("resolver/hosts.zig");
    _ = @import("resolver/reload.zig");
    _ = @import("resolver/rotation.zig");
}
