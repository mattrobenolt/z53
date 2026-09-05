const std = @import("std");

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
        if (address[0] == '[') {
            const close = std.mem.indexOfScalar(u8, address, ']') orelse
                return error.InvalidAddress;
            const host = address[1..close];
            _ = std.Io.net.Ip6Address.parse(host, 0) catch return error.InvalidAddress;
            if (close + 1 == address.len) {
                target.* = .{ .host = host, .port = port_default };
                return;
            }
            if (address[close + 1] != ':') return error.InvalidAddress;
            target.* = .{ .host = host, .port = try parsePort(address[close + 2 ..]) };
            return;
        }
        const colon = std.mem.indexOfScalar(u8, address, ':') orelse address.len;
        const host = address[0..colon];
        try validateHost(host);
        const port = if (colon == address.len)
            port_default
        else
            try parsePort(address[colon + 1 ..]);
        target.* = .{ .host = host, .port = port };
    }
};

fn parsePort(text: []const u8) error{InvalidAddress}!u16 {
    if (text.len == 0) return error.InvalidAddress;
    for (text) |byte| {
        if (!std.ascii.isDigit(byte)) return error.InvalidAddress;
    }
    const port = std.fmt.parseInt(u16, text, 10) catch return error.InvalidAddress;
    if (port == 0) return error.InvalidAddress;
    return port;
}

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
