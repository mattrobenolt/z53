const std = @import("std");
const system = std.c;
const wire = @import("../wire.zig");
const udp = @import("udp.zig");

pub const Response = struct {
    listener: ?u16 = null,
    address: system.sockaddr.storage,
    address_length: system.socklen_t,
    length: u32,
    output: [wire.message_bytes_max]u8,
};

pub fn family(
    source: *const system.sockaddr.storage,
    length: system.socklen_t,
) error{InvalidDatagram}!udp.Family {
    const expected: system.socklen_t = switch (source.family) {
        system.AF.INET => @sizeOf(system.sockaddr.in),
        system.AF.INET6 => @sizeOf(system.sockaddr.in6),
        else => return error.InvalidDatagram,
    };
    if (length != expected) return error.InvalidDatagram;
    if (source.len != expected) return error.InvalidDatagram;
    return if (source.family == system.AF.INET) .ipv4 else .ipv6;
}
