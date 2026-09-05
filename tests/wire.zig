// SPEC §9.1: the wire suite is separate from TLS foundation tests.
test {
    _ = @import("wire/names.zig");
    _ = @import("wire/opaque.zig");
    _ = @import("wire/records.zig");
    _ = @import("wire/rewrite.zig");
    _ = @import("wire/limits.zig");
    _ = @import("wire/extra.zig");
}
