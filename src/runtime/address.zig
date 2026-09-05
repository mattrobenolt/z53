const std = @import("std");
const linux = std.os.linux;
const config = @import("../config.zig");
pub const Error = error{ UnresolvedListener, SocketFailed, BindFailed, ListenFailed };

pub const Address = struct {
    storage: linux.sockaddr.storage,
    length: linux.socklen_t,

    pub fn parse(self: *Address, text: []const u8) Error!void {
        var endpoint: config.Endpoint = undefined;
        endpoint.parse(text, 53) catch unreachable;
        // #1: bootstrap must add listener hostname resolution before final acceptance.
        const ip = std.Io.net.IpAddress.parse(endpoint.host, endpoint.port) catch
            return error.UnresolvedListener;
        self.storage = std.mem.zeroes(linux.sockaddr.storage);
        switch (ip) {
            .ip4 => |value| {
                const address: *linux.sockaddr.in = @ptrCast(&self.storage);
                address.* = .{
                    .port = std.mem.nativeToBig(u16, value.port),
                    .addr = @bitCast(value.bytes),
                };
                self.length = @sizeOf(linux.sockaddr.in);
            },
            .ip6 => |value| {
                const address: *linux.sockaddr.in6 = @ptrCast(&self.storage);
                address.* = .{
                    .port = std.mem.nativeToBig(u16, value.port),
                    .addr = value.bytes,
                    .flowinfo = value.flow,
                    .scope_id = value.interface.index,
                };
                self.length = @sizeOf(linux.sockaddr.in6);
            },
        }
    }

    pub fn bind(self: *const Address, kind: u32) Error!linux.fd_t {
        const flags = kind | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK;
        const result = linux.socket(self.storage.family, flags, 0);
        if (linux.errno(result) != .SUCCESS) return error.SocketFailed;
        const descriptor: linux.fd_t = @intCast(result);
        errdefer _ = linux.close(descriptor);
        if (self.storage.family == linux.AF.INET6) {
            const one: u32 = 1;
            const option = linux.setsockopt(
                descriptor,
                linux.IPPROTO.IPV6,
                linux.IPV6.V6ONLY,
                std.mem.asBytes(&one).ptr,
                4,
            );
            if (linux.errno(option) != .SUCCESS) return error.SocketFailed;
        }
        if (kind == linux.SOCK.STREAM) {
            // Configuration restarts must bind while server-closed clients remain in TIME_WAIT.
            const one: u32 = 1;
            const option = linux.setsockopt(
                descriptor,
                linux.SOL.SOCKET,
                linux.SO.REUSEADDR,
                std.mem.asBytes(&one).ptr,
                @sizeOf(u32),
            );
            if (linux.errno(option) != .SUCCESS) return error.SocketFailed;
        }
        const bound = linux.bind(descriptor, @ptrCast(&self.storage), self.length);
        if (linux.errno(bound) != .SUCCESS) return error.BindFailed;
        if (kind == linux.SOCK.STREAM) {
            if (linux.errno(linux.listen(descriptor, 128)) != .SUCCESS) return error.ListenFailed;
        }
        return descriptor;
    }
};
