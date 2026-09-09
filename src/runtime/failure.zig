const std = @import("std");
const testing = std.testing;
const engine = @import("ztls");

pub const Reason = union(enum) {
    transport_failure,
    local_resource,
    timeout,
    socket: std.posix.E,
    handshake: engine.errors.HandshakeError,
    tls_io: error{ TransportFailure, LocalFailure },

    pub fn message(self: Reason) []const u8 {
        return switch (self) {
            .socket => |err| @tagName(err),
            .handshake => |err| @errorName(err),
            .tls_io => |err| @errorName(err),
            else => @tagName(self),
        };
    }
};

// SPEC §4: diagnostic labels preserve the specific cause without string-valued state.
test "failure reasons format only at the diagnostic boundary" {
    const cases = .{
        .{ @as(Reason, .transport_failure), "transport_failure" },
        .{ @as(Reason, .local_resource), "local_resource" },
        .{ @as(Reason, .timeout), "timeout" },
        .{ Reason{ .socket = .CONNREFUSED }, "CONNREFUSED" },
        .{ Reason{ .handshake = error.CertificateIssuerNotFound }, "CertificateIssuerNotFound" },
        .{ Reason{ .tls_io = error.TransportFailure }, "TransportFailure" },
        .{ Reason{ .tls_io = error.LocalFailure }, "LocalFailure" },
    };
    inline for (cases) |case| try testing.expectEqualStrings(case[1], case[0].message());
}
