//! Read exactly one frame before each response. Coalesced queries remain in the socket.
const std = @import("std");
const wire = @import("../wire.zig");
pub const clients_max = 128;
pub const Client = struct {
    state: enum { vacant, connected, closing, replacing } = .vacant,
    phase: enum { prefix, body, response } = .prefix,
    offset: u32 = 0,
    length: u32 = 2,
    input: [wire.message_bytes_max + 2]u8,
    output: [wire.message_bytes_max + 2]u8,

    pub fn reset(self: *Client) void {
        self.state = .connected;
        self.nextQuery();
    }

    pub fn nextQuery(self: *Client) void {
        self.phase = .prefix;
        self.offset = 0;
        self.length = 2;
    }

    pub fn received(self: *Client, count: i32) error{ Closed, InvalidFrame }!?[]const u8 {
        if (count <= 0) return error.Closed;
        if (@as(u32, @intCast(count)) > self.length - self.offset) return error.InvalidFrame;
        self.offset += @intCast(count);
        if (self.offset < self.length) return null;
        switch (self.phase) {
            .prefix => {
                const length: u32 = wire.integer(u16, self.input[0..2]);
                if (length < 12) return error.InvalidFrame;
                self.length = length + 2;
                self.phase = .body;
                return null;
            },
            .body => return self.input[2..self.length],
            .response => unreachable,
        }
    }

    pub fn respond(self: *Client, length: usize) void {
        std.debug.assert(length >= 12);
        std.debug.assert(length <= wire.message_bytes_max);
        wire.framePrefix(&self.output, length) catch unreachable;
        self.phase = .response;
        self.offset = 0;
        self.length = @intCast(length + 2);
    }

    pub fn sent(self: *Client, count: i32) error{ Closed, InvalidFrame }!void {
        std.debug.assert(self.phase == .response);
        if (count <= 0) return error.Closed;
        if (@as(u32, @intCast(count)) > self.length - self.offset) return error.InvalidFrame;
        self.offset += @intCast(count);
        if (self.offset == self.length) self.nextQuery();
    }
};
