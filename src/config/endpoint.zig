const std = @import("std");
const Io = std.Io;
const HostPort = @import("stdx").net.HostPort;

pub const Endpoint = struct {
    host: []const u8,
    port: u16,

    /// Unbracketed IPv6 is not an endpoint: brackets disambiguate the port.
    pub fn parse(
        target: *Endpoint,
        address: []const u8,
        port_default: u16,
    ) error{InvalidAddress}!void {
        errdefer target.* = undefined;
        if (address.len == 0) return error.InvalidAddress;
        if (address.len > 320) return error.InvalidAddress;
        const parsed = HostPort.parse(address, port_default) catch return error.InvalidAddress;
        if (address[0] == '[') {
            _ = Io.net.Ip6Address.parse(parsed.host, 0) catch return error.InvalidAddress;
        } else {
            try validateHost(parsed.host);
        }
        target.* = .{ .host = parsed.host, .port = parsed.port };
    }
};

pub fn validateHost(host: []const u8) error{InvalidAddress}!void {
    if (host.len == 0) return error.InvalidAddress;
    if (host.len > 253) return error.InvalidAddress;
    const end = host.len - @intFromBool(host[host.len - 1] == '.');
    var labels = std.mem.splitScalar(u8, host[0..end], '.');
    while (labels.next()) |label| {
        if (label.len == 0) return error.InvalidAddress;
        if (label.len > 63) return error.InvalidAddress;
        if (label[0] == '-') return error.InvalidAddress;
        if (label[label.len - 1] == '-') return error.InvalidAddress;
        for (label) |byte| {
            if (std.ascii.isAlphanumeric(byte)) continue;
            if (byte == '-') continue;
            return error.InvalidAddress;
        }
    }
}
