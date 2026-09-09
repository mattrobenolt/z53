const builtin = @import("builtin");
const runtime = @import("../runtime.zig");
const std = @import("std");
const linux = std.os.linux;
const assert = std.debug.assert;

const wire = @import("../wire.zig");
const log = @import("log.zig");

const udp_header_bytes = 8;
const ipv4_header_bytes = 20;

pub const Family = enum { ipv4, ipv6 };

pub const Datagram = struct {
    address: []const u8,
    payload: []const u8,
    family: Family,
};

/// Ordinary datagrams have fixed IP headers and no IPv6 jumbogram option.
pub fn limit(client_bytes: u16, family: Family) u16 {
    const maximum: u16 = switch (family) {
        .ipv4 => std.math.maxInt(u16) - ipv4_header_bytes - udp_header_bytes,
        .ipv6 => std.math.maxInt(u16) - udp_header_bytes,
    };
    return @min(@max(wire.udp_payload_bytes_default, client_bytes), maximum);
}
pub const Response = struct {
    state: enum { free, reserved, sending } = .free,
    observation: log.Query,
    generation: u31 = 0,
    listener: u16,
    address: linux.sockaddr.storage,
    vector: std.posix.iovec_const,
    message: linux.msghdr_const,
    output: [wire.message_bytes_max]u8,

    pub fn prepare(self: *Response, datagram: *const Datagram, length: usize) void {
        assert(self.state == .reserved);
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

comptime {
    if (builtin.is_test) _ = RuntimeUnitTests;
}

const RuntimeUnitTests = struct {
    const testing = std.testing;

    // SPEC §3.9: truncated recvmsg payloads never become partial DNS requests.
    test "UDP recvmsg metadata bounds" {
        if (builtin.os.tag != .linux) return error.SkipZigTest;
        var bytes: [runtime.proctor.buffer_bytes]u8 = @splat(0);
        var header: linux.io_uring_recvmsg_out = .{
            .namelen = 16,
            .controllen = 0,
            .payloadlen = 12,
            .flags = 0,
        };
        @memcpy(bytes[0..16], std.mem.asBytes(&header));
        const family: linux.sa_family_t = linux.AF.INET;
        @memcpy(bytes[16..18], std.mem.asBytes(&family));
        try testing.expectEqual(
            @as(usize, 12),
            (try runtime.udp.decode(bytes[0..156])).payload.len,
        );
        try testing.expectError(error.InvalidDatagram, runtime.udp.decode(bytes[0..155]));
        header.flags = linux.MSG.TRUNC;
        @memcpy(bytes[0..16], std.mem.asBytes(&header));
        try testing.expectError(error.InvalidDatagram, runtime.udp.decode(bytes[0..156]));
    }

    // RFC 768; RFC 791 §3.1; RFC 8200 §3; SPEC §3.9: fixed-header UDP payload ceilings.
    test "IPv4 and IPv6 UDP exact caps and complete RRset truncation" {
        const fixture = try testing.allocator.create(struct {
            encoder: wire.Encoder,
            rewrite: wire.rewrite.Workspace,
            packet: wire.Packet,
            input: [65535]u8,
            output: [65535]u8,
            data: [65535]u8,
        });
        defer testing.allocator.destroy(fixture);
        @memset(&fixture.data, 0);
        var name: wire.Name = undefined;
        try name.fromText(".");
        for ([_]runtime.udp.Family{ .ipv4, .ipv6 }) |family| {
            const cap: u16 = if (family == .ipv4) 65507 else 65527;
            try testing.expectEqual(@as(u16, 512), runtime.udp.limit(0, family));
            try testing.expectEqual(cap, runtime.udp.limit(cap, family));
            try testing.expectEqual(cap, runtime.udp.limit(cap + 1, family));
            for (0..2) |extra| {
                try fixture.encoder.init(&fixture.input, &.{ .bits = 0x8000 });
                try fixture.encoder.question(&name, @enumFromInt(65400), 1);
                const record: wire.Record = .{
                    .owner = 0,
                    .kind = @enumFromInt(65400),
                    .class = 1,
                    .ttl_s = 30,
                    .data_start = 0,
                    .data_end = 0,
                    .section = .answer,
                };
                const start = try fixture.encoder.beginRecord(&name, &record);
                try fixture.encoder.bytes(fixture.data[0 .. @as(usize, cap) - 39 + extra]);
                fixture.encoder.endRecord(start);
                try wire.rewrite.writeOpt(&fixture.encoder, &.{ .payload_bytes = 65535 });
                const input = try fixture.encoder.finish();
                try testing.expectEqual(@as(usize, cap) + extra, input.len);
                try fixture.packet.parse(input);
                const settings: wire.rewrite.Settings = .{
                    .limit = .{ .udp = runtime.udp.limit(65535, family) },
                };
                const output = try fixture.rewrite.rewrite(
                    &fixture.packet,
                    &fixture.output,
                    &settings,
                );
                try testing.expect(output.len <= cap);
                try fixture.packet.parse(output);
                try testing.expectEqual(extra == 1, fixture.packet.header.has(.truncated));
                try testing.expectEqual(1 - extra, fixture.packet.header.counts[1]);
                try testing.expectEqual(65535, fixture.packet.records[fixture.packet.opt.?].class);
            }
        }
    }
};
