const std = @import("std");
const linux = std.os.linux;
const wire = @import("../wire.zig");
pub const Family = enum { ipv4, ipv6 };
pub const Datagram = struct { address: []const u8, payload: []const u8, family: Family };

/// Ordinary datagrams have fixed IP headers and no IPv6 jumbogram option.
pub fn limit(client_bytes: u16, family: Family) u16 {
    const maximum: u16 = switch (family) {
        .ipv4 => 65507,
        .ipv6 => 65527,
    };
    return @min(@max(512, client_bytes), maximum);
}
pub const Response = struct {
    state: enum { free, sending } = .free,
    address: linux.sockaddr.storage,
    vector: std.posix.iovec_const,
    message: linux.msghdr_const,
    output: [wire.message_bytes_max]u8,

    pub fn prepare(self: *Response, datagram: *const Datagram, length: usize) void {
        std.debug.assert(self.state == .free);
        @memcpy(std.mem.asBytes(&self.address)[0..datagram.address.len], datagram.address);
        self.vector = .{ .base = &self.output, .len = length };
        self.message = .{
            .name = @ptrCast(&self.address),
            .namelen = @intCast(datagram.address.len),
            .iov = @ptrCast(&self.vector),
            .iovlen = 1,
            .control = null,
            .controllen = 0,
            .flags = 0,
        };
        self.state = .sending;
    }
};

/// io_uring RECVMSG reserves the requested name/control capacities, not their actual sizes.
pub fn decode(bytes: []const u8) error{InvalidDatagram}!Datagram {
    const prefix = @sizeOf(linux.io_uring_recvmsg_out);
    const payload_offset = prefix + @sizeOf(linux.sockaddr.storage);
    if (bytes.len < payload_offset) return error.InvalidDatagram;
    const header = std.mem.bytesToValue(linux.io_uring_recvmsg_out, bytes[0..prefix]);
    if (header.flags & (linux.MSG.TRUNC | linux.MSG.CTRUNC) != 0) return error.InvalidDatagram;
    if (header.controllen != 0) return error.InvalidDatagram;
    if (header.namelen > @sizeOf(linux.sockaddr.storage)) return error.InvalidDatagram;
    if (header.namelen < @sizeOf(linux.sa_family_t)) return error.InvalidDatagram;
    const address = bytes[prefix..][0..header.namelen];
    const family = std.mem.bytesToValue(linux.sa_family_t, address[0..2]);
    const expected: usize = switch (family) {
        linux.AF.INET => @sizeOf(linux.sockaddr.in),
        linux.AF.INET6 => @sizeOf(linux.sockaddr.in6),
        else => return error.InvalidDatagram,
    };
    if (address.len != expected) return error.InvalidDatagram;
    if (header.payloadlen > bytes.len - payload_offset) return error.InvalidDatagram;
    if (header.payloadlen > wire.message_bytes_max) return error.InvalidDatagram;
    return .{
        .address = address,
        .payload = bytes[payload_offset..][0..header.payloadlen],
        .family = if (family == linux.AF.INET) .ipv4 else .ipv6,
    };
}
