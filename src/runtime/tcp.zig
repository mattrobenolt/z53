//! Read exactly one frame before each response. Coalesced queries remain in the socket.
const builtin = @import("builtin");
const runtime = @import("../runtime.zig");
const std = @import("std");
const assert = std.debug.assert;

const wire = @import("../wire.zig");
const log = @import("log.zig");

pub const clients_max = 128;

pub const Client = struct {
    state: enum { vacant, connected, closing, replacing } = .vacant,
    phase: enum { prefix, body, waiting, response } = .prefix,
    observation: log.Query,
    generation: u31 = 0,
    offset: u32 = 0,
    length: u32 = 2,
    input: [wire.message_bytes_max + wire.frame_prefix_bytes]u8,
    output: [wire.message_bytes_max + wire.frame_prefix_bytes]u8,

    pub fn reset(self: *Client) void {
        // Runtime admission checks exhaustion before it resets a connection.
        assert(self.generation < std.math.maxInt(u31));
        self.generation += 1;
        self.state = .connected;
        self.nextQuery();
    }

    pub fn nextQuery(self: *Client) void {
        self.phase = .prefix;
        self.offset = 0;
        self.length = wire.frame_prefix_bytes;
    }

    pub fn received(self: *Client, count: i32) error{ Closed, InvalidFrame }!?[]const u8 {
        if (count <= 0) return error.Closed;
        if (@as(u32, @intCast(count)) > self.length - self.offset) return error.InvalidFrame;
        self.offset += @intCast(count);
        if (self.offset < self.length) return null;
        switch (self.phase) {
            .prefix => {
                const length: u32 = wire.integer(u16, self.input[0..wire.frame_prefix_bytes]);
                if (length < wire.header_bytes) return error.InvalidFrame;
                self.length = length + wire.frame_prefix_bytes;
                self.phase = .body;
                return null;
            },
            .body => return self.input[2..self.length],
            .waiting, .response => unreachable,
        }
    }

    pub fn respond(self: *Client, length: usize) void {
        assert(length >= wire.header_bytes);
        assert(length <= wire.message_bytes_max);
        wire.framePrefix(&self.output, length) catch unreachable;
        self.phase = .response;
        self.offset = 0;
        self.length = @intCast(length + wire.frame_prefix_bytes);
    }

    pub fn sent(self: *Client, count: i32) error{ Closed, InvalidFrame }!void {
        assert(self.phase == .response);
        if (count <= 0) return error.Closed;
        if (@as(u32, @intCast(count)) > self.length - self.offset) return error.InvalidFrame;
        self.offset += @intCast(count);
        if (self.offset == self.length) self.nextQuery();
    }
};

comptime {
    if (builtin.is_test) _ = RuntimeUnitTests;
}

const RuntimeUnitTests = struct {
    const testing = std.testing;
    const linux = std.os.linux;

    // RFC 1035 §4.2.2: fragmented framing, partial sends, and repeated queries are bounded.
    test "TCP partial framing and repeated responses" {
        const client = try testing.allocator.create(runtime.tcp.Client);
        defer testing.allocator.destroy(client);
        client.generation = 0;
        client.reset();
        client.input[0..2].* = .{ 0, 12 };
        try testing.expectEqual(null, try client.received(1));
        try testing.expectEqual(null, try client.received(1));
        try testing.expectEqual(null, try client.received(5));
        try testing.expectEqual(@as(usize, 12), (try client.received(7)).?.len);
        client.respond(12);
        try client.sent(3);
        try testing.expectEqual(.response, client.phase);
        try client.sent(11);
        try testing.expectEqual(.prefix, client.phase);
        client.input[0..2].* = .{ 0, 11 };
        try testing.expectError(error.InvalidFrame, client.received(2));
        client.nextQuery();
        try testing.expectError(error.Closed, client.received(0));
        try testing.expectError(error.InvalidFrame, client.received(3));
    }

    // RFC 1035 §4.2.2; SPEC §3.9: both backends reject completion overruns without wrapping.
    test "TCP framing partial overruns and maximum message length" {
        const client = try testing.allocator.create(runtime.tcp.Client);
        defer testing.allocator.destroy(client);
        client.generation = 0;
        client.reset();
        client.input[0..2].* = .{ 0, 12 };
        try testing.expectEqual(null, try client.received(1));
        try testing.expectError(error.InvalidFrame, client.received(2));
        try testing.expectEqual(1, client.offset);
        client.respond(12);
        try client.sent(1);
        try testing.expectError(error.InvalidFrame, client.sent(14));
        try testing.expectEqual(1, client.offset);
        client.generation = 0;
        client.reset();
        client.input[0..2].* = .{ 255, 255 };
        try testing.expectEqual(null, try client.received(2));
        try testing.expectEqual(65537, client.length);
        try testing.expectEqual(@as(usize, 65535), (try client.received(65535)).?.len);
        client.respond(65535);
        try testing.expectEqualSlices(u8, &.{ 255, 255 }, client.output[0..2]);
        try client.sent(65537);
        try testing.expectEqual(.prefix, client.phase);
    }
};
