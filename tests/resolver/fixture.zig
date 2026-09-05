const std = @import("std");
pub const resolver = @import("resolver");
pub const wire = resolver.wire;
pub const testing = std.testing;
pub const zone: resolver.config.Zone = .{
    .suffix = ".",
    .upstreams = &.{.{ .address = "127.0.0.1:5300" }},
    .hosts = .{},
    .nodata = &.{.AAAA},
    .rotate = true,
};

pub const Fixture = struct {
    input: [wire.message_bytes_max]u8,
    output: [wire.message_bytes_max]u8,
    encoder: wire.Encoder,
    query: wire.Packet,
    response: wire.Packet,
    request: resolver.Request,

    pub fn init(self: *Fixture, name: []const u8, kind: u16, class: u16) !void {
        var expanded: wire.Name = undefined;
        try expanded.fromText(name);
        const header: wire.Header = .{ .id = 0x1234, .bits = 0x01b0 };
        try self.encoder.init(&self.input, &header);
        try self.encoder.question(&expanded, kind, class);
        const bytes = try self.encoder.finish();
        try self.query.parse(bytes);
        try self.request.init(&self.query);
    }

    pub fn edns(self: *Fixture, options: []const u8) !void {
        const value: wire.rewrite.Edns = .{
            .payload_bytes = 1400,
            .flags = 0x8000,
            .options = options,
        };
        try wire.rewrite.writeOpt(&self.encoder, &value);
        try self.query.parse(try self.encoder.finish());
        try self.request.init(&self.query);
    }

    pub fn local(self: *Fixture) !?resolver.Answer {
        return resolver.beforeCache(&self.request, &self.encoder, &self.output);
    }

    pub fn after(
        self: *Fixture,
        settings: *const resolver.config.Zone,
        table: ?*const resolver.hosts.Table,
    ) !?resolver.Answer {
        return resolver.afterCache(&self.request, settings, table, &self.encoder, &self.output);
    }

    pub fn check(self: *Fixture, answer: *const resolver.Answer, count: u16) !void {
        try self.response.parse(answer.bytes);
        try testing.expectEqual(@as(u16, 0x1234), self.response.header.id);
        try testing.expectEqual(@as(u16, 0x8510), self.response.header.bits);
        try testing.expectEqual(count, self.response.header.counts[1]);
        try testing.expectEqual(@as(u16, 0), self.response.header.counts[2]);
        var cursor: usize = 12;
        const question = try self.response.readQuestion(&cursor);
        var name: wire.Name = undefined;
        try self.response.name(&name, question.name);
        try testing.expectEqualSlices(u8, self.request.name.wire(), name.wire());
        try testing.expectEqual(self.request.kind, question.kind);
        try testing.expectEqual(self.request.class, question.class);
        try testing.expect(!answer.source.cacheable());
    }
};
