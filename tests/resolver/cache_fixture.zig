const std = @import("std");
const f = @import("fixture.zig");
pub const testing = std.testing;
pub const resolver = f.resolver;
pub const wire = f.wire;
pub const cache = resolver.cache;
pub const Fixture = struct {
    client: f.Fixture,
    upstream: [wire.message_bytes_max]u8,
    encoder: wire.Encoder,
    workspace: cache.Workspace,
    cache: cache.Cache,

    pub fn init(
        self: *Fixture,
        allocator: std.mem.Allocator,
        settings: *const resolver.config.Zone,
    ) !void {
        try self.cache.init(allocator, settings);
        try self.client.init("example.", 1, 1);
    }

    pub fn response(self: *Fixture, bits: u16) !void {
        const header: wire.Header = .{ .id = 999, .bits = bits };
        try self.encoder.init(&self.upstream, &header);
        try self.encoder.question(
            &self.client.request.name,
            self.client.request.kind,
            self.client.request.class,
        );
    }

    pub fn record(
        self: *Fixture,
        kind: u16,
        section: wire.Section,
        ttl_s: u32,
        minimum_s: u32,
    ) !void {
        const value: wire.Record = .{
            .owner = 0,
            .kind = kind,
            .class = self.client.request.class,
            .ttl_s = ttl_s,
            .data_start = 0,
            .data_end = 0,
            .section = section,
        };
        const offset = try self.encoder.beginRecord(&self.client.request.name, &value);
        switch (kind) {
            1 => try self.encoder.bytes(&.{ 192, 0, 2, 1 }),
            5 => try self.encoder.name(&self.client.request.name, .allowed),
            6 => {
                try self.encoder.name(&self.client.request.name, .allowed);
                try self.encoder.name(&self.client.request.name, .allowed);
                for (0..4) |_| try self.encoder.number(u32, 0);
                try self.encoder.number(u32, minimum_s);
            },
            else => unreachable,
        }
        self.encoder.endRecord(offset);
    }

    pub fn forward(self: *Fixture, now_s: u64) !cache.Result {
        return self.cache.forward(
            &self.client.request,
            try self.encoder.finish(),
            now_s,
            &self.workspace,
            &self.client.output,
        );
    }

    pub fn lookup(self: *Fixture, now_s: u64) !?resolver.Answer {
        return self.cache.lookup(&self.client.request, now_s, &self.workspace, &self.client.output);
    }

    pub fn failure(self: *Fixture, now_s: u64) !cache.Result {
        return self.cache.terminalFailure(
            &self.client.request,
            now_s,
            &self.workspace,
            &self.client.output,
        );
    }

    pub fn ttl(self: *Fixture, answer: *const resolver.Answer, expected_s: u32) !void {
        try self.client.response.parse(answer.bytes);
        try testing.expectEqual(expected_s, self.client.response.records[0].ttl_s);
    }
};
pub const zone: resolver.config.Zone = .{
    .suffix = ".",
    .upstreams = &.{.{ .address = "127.0.0.1:5300" }},
    .cache = .{ .capacity = 2 },
    .serve_stale_s = 10,
};
