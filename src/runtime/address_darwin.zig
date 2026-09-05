const std = @import("std");
const system = std.c;
const config = @import("../config.zig");
// Zig's bundled libc/include/any-darwin-any/netinet6/in6.h defines IPV6_V6ONLY.
// std.c.IPV6 is void on Darwin in Zig 0.16, so name the verified ABI constant here.
const ipv6_v6only = 27;
pub const Error = error{ UnresolvedListener, SocketFailed, BindFailed, ListenFailed };

pub const Address = struct {
    storage: system.sockaddr.storage,
    length: system.socklen_t,

    pub fn parse(self: *Address, text: []const u8) Error!void {
        var endpoint: config.Endpoint = undefined;
        endpoint.parse(text, 53) catch unreachable;
        // #1: bootstrap must add listener hostname resolution before final acceptance.
        const ip = std.Io.net.IpAddress.parse(endpoint.host, endpoint.port) catch
            return error.UnresolvedListener;
        self.storage = std.mem.zeroes(system.sockaddr.storage);
        switch (ip) {
            .ip4 => |value| {
                const address: *system.sockaddr.in = @ptrCast(&self.storage);
                address.* = .{
                    .port = std.mem.nativeToBig(u16, value.port),
                    .addr = @bitCast(value.bytes),
                };
                self.length = @sizeOf(system.sockaddr.in);
            },
            .ip6 => |value| {
                const address: *system.sockaddr.in6 = @ptrCast(&self.storage);
                address.* = .{
                    .port = std.mem.nativeToBig(u16, value.port),
                    .addr = value.bytes,
                    .flowinfo = value.flow,
                    .scope_id = value.interface.index,
                };
                self.length = @sizeOf(system.sockaddr.in6);
            },
        }
    }

    pub fn bind(self: *const Address, kind: u32) Error!system.fd_t {
        const descriptor = system.socket(self.storage.family, kind, 0);
        if (descriptor < 0) return error.SocketFailed;
        errdefer _ = system.close(descriptor);
        try prepare(descriptor);
        if (self.storage.family == system.AF.INET6)
            try option(descriptor, system.IPPROTO.IPV6, ipv6_v6only);
        if (kind == system.SOCK.STREAM) {
            // Keep the Linux restart policy: address reuse, never port reuse.
            try option(descriptor, system.SOL.SOCKET, system.SO.REUSEADDR);
        }
        if (system.bind(descriptor, @ptrCast(&self.storage), self.length) < 0)
            return error.BindFailed;
        if (kind == system.SOCK.STREAM) {
            if (system.listen(descriptor, 128) < 0) return error.ListenFailed;
        }
        return descriptor;
    }
};

/// Darwin does not accept SOCK_NONBLOCK or SOCK_CLOEXEC in socket/accept.
pub fn prepare(descriptor: system.fd_t) Error!void {
    const flags = system.fcntl(descriptor, system.F.GETFL);
    if (flags < 0) return error.SocketFailed;
    const nonblocking: c_int = @bitCast(@as(system.O, .{ .NONBLOCK = true }));
    if (system.fcntl(descriptor, system.F.SETFL, flags | nonblocking) < 0)
        return error.SocketFailed;
    if (system.fcntl(descriptor, system.F.SETFD, @as(c_int, system.FD_CLOEXEC)) < 0)
        return error.SocketFailed;
    // A closed peer must return EPIPE, not terminate the event thread with SIGPIPE.
    try option(descriptor, system.SOL.SOCKET, system.SO.NOSIGPIPE);
}

fn option(descriptor: system.fd_t, level: i32, name: u32) Error!void {
    const one: u32 = 1;
    if (system.setsockopt(descriptor, level, name, &one, @sizeOf(u32)) < 0)
        return error.SocketFailed;
}
