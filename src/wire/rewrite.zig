const builtin = @import("builtin");
const std = @import("std");
const fixture = @import("../testing/wire.zig");
const ArrayBuffer = @import("../array_buffer.zig").ArrayBuffer;
const wire = @import("../wire.zig");

pub const Edns = struct {
    payload_bytes: u16,
    extended_rcode: u8 = 0,
    version: u8 = 0,
    flags: u16 = 0,
    options: []const u8 = &.{},
};

pub const OptPolicy = union(enum) {
    preserve,
    omit,
    replace: *const Edns,
};

pub const Limit = union(enum) {
    tcp,
    udp: u16,
};

pub const Question = struct {
    name: *const wire.Name,
    kind: wire.RecordType,
    class: u16,
};

pub const Settings = struct {
    id: ?u16 = null,
    question: ?Question = null,
    opt: OptPolicy = .preserve,
    limit: Limit = .tcp,
    /// Empty means original order. Otherwise this must be a complete permutation.
    order: []const u16 = &.{},
};

/// One synchronous workspace, owned by the event thread. No query heap use.
pub const Workspace = struct {
    encoder: wire.Encoder,
    order: ArrayBuffer(u16, wire.records_max),
    seen: wire.names.ScratchSet(wire.records_max),

    pub fn rewrite(
        self: *Workspace,
        packet: *wire.Packet,
        output: []u8,
        settings: *const Settings,
    ) wire.Error![]const u8 {
        try self.prepare(packet, settings);
        const opt = try edns(packet, &settings.opt);
        const reserve: usize = if (opt) |value| wire.opt_record_bytes + value.options.len else 0;
        const limit: usize = switch (settings.limit) {
            .tcp => wire.message_bytes_max,
            .udp => |size| @max(wire.udp_payload_bytes_default, size),
        };
        const capacity = @min(output.len, limit);
        const overflow: wire.Error = switch (settings.limit) {
            .tcp => if (output.len < wire.message_bytes_max)
                error.NoSpace
            else
                error.RewriteTooLarge,
            .udp => error.NoSpace,
        };
        if (reserve > capacity) return overflow;
        self.start(packet, output[0 .. capacity - reserve], settings) catch |err| {
            return if (err == error.NoSpace) overflow else err;
        };
        var cutoff: u16 = self.order.len;
        for (self.order.constSlice(), 0..) |index, position| {
            self.encoder.record(packet, &packet.records[index]) catch |err| {
                if (err != error.NoSpace) return err;
                switch (settings.limit) {
                    .tcp => return overflow,
                    .udp => cutoff = @intCast(position),
                }
                break;
            };
        }
        if (cutoff < self.order.len) {
            cutoff = try self.wholeSets(packet, cutoff);
            try self.start(packet, output[0 .. capacity - reserve], settings);
            self.encoder.header.bits |= @intFromEnum(wire.Flag.truncated);
            for (self.order.constSlice()[0..cutoff]) |index| {
                try self.encoder.record(packet, &packet.records[index]);
            }
        }
        self.encoder.output = output[0..capacity];
        if (opt) |value| try writeOpt(&self.encoder, &value);
        return self.encoder.finish();
    }

    fn prepare(
        self: *Workspace,
        packet: *const wire.Packet,
        settings: *const Settings,
    ) wire.Error!void {
        if (settings.order.len != 0) {
            if (settings.order.len != packet.record_count) return error.InvalidOrder;
        }
        self.seen.init();
        self.order.clear();
        var previous: wire.Section = .question;
        for (0..packet.record_count) |position| {
            const index: u16 = if (settings.order.len == 0)
                @intCast(position)
            else
                settings.order[position];
            if (index >= packet.record_count) return error.InvalidOrder;
            if (self.seen.isSet(index)) return error.InvalidOrder;
            self.seen.set(index);
            const record = &packet.records[index];
            if (@intFromEnum(record.section) < @intFromEnum(previous)) return error.InvalidOrder;
            previous = record.section;
            if (record.kind == .opt) continue;
            // Packet validation bounds the complete list, including omitted OPT records.
            self.order.appendAssumeCapacity(index);
        }
    }

    fn start(
        self: *Workspace,
        packet: *wire.Packet,
        output: []u8,
        settings: *const Settings,
    ) wire.Error!void {
        try self.encoder.init(output, &packet.header);
        if (settings.id) |id| self.encoder.header.id = id;
        if (settings.question) |question| {
            try self.encoder.question(question.name, question.kind, question.class);
        } else {
            var cursor: usize = wire.header_bytes;
            for (0..packet.header.counts[0]) |_| {
                const question = try packet.readQuestion(&cursor);
                var name: wire.Name = undefined;
                try packet.name(&name, question.name);
                try self.encoder.question(&name, question.kind, question.class);
            }
        }
    }

    fn wholeSets(self: *const Workspace, packet: *const wire.Packet, initial: u16) wire.Error!u16 {
        var cutoff = initial;
        // Descending traversal closes over all sets split by an earlier cut.
        var left: usize = initial;
        while (left > 0) {
            left -= 1;
            for (cutoff..self.order.len) |right| {
                const source = &packet.records[self.order.constSlice()[left]];
                const target = &packet.records[self.order.constSlice()[right]];
                if (try sameSet(packet, source, target)) {
                    cutoff = @intCast(left);
                    break;
                }
            }
        }
        return cutoff;
    }
};

fn sameSet(
    packet: *const wire.Packet,
    left: *const wire.Record,
    right: *const wire.Record,
) wire.Error!bool {
    if (left.section != right.section) return false;
    if (left.kind != right.kind) return false;
    if (left.class != right.class) return false;
    var source: wire.Name = undefined;
    var target: wire.Name = undefined;
    try packet.name(&source, left.owner);
    try packet.name(&target, right.owner);
    return source.eql(&target);
}

fn edns(packet: *const wire.Packet, policy: *const OptPolicy) wire.Error!?Edns {
    switch (policy.*) {
        .omit => return null,
        .replace => |value| {
            try validateOptions(value.options);
            return value.*;
        },
        .preserve => {
            const index = packet.opt orelse return null;
            const record = &packet.records[index];
            return .{
                .payload_bytes = record.class,
                .extended_rcode = @truncate(record.ttl_s >> wire.edns_rcode_shift),
                .version = @truncate(record.ttl_s >> wire.edns_version_shift),
                .flags = @truncate(record.ttl_s),
                .options = packet.bytes[record.data_start..record.data_end],
            };
        },
    }
}

pub fn validateOptions(options: []const u8) wire.Error!void {
    if (options.len > wire.message_bytes_max - wire.opt_record_bytes) return error.InvalidOption;
    var iterator: wire.Options = .{ .bytes = options };
    var cookie: ?[]const u8 = null;
    while (try iterator.next()) |option| {
        if (option.code == wire.cookie_option_code) {
            if (cookie != null) return error.InvalidCookie;
            try wire.validateCookie(option.data);
            cookie = option.data;
        }
    }
}

pub fn writeOpt(encoder: *wire.Encoder, value: *const Edns) wire.Error!void {
    try validateOptions(value.options);
    var root: wire.Name = undefined;
    try root.fromText(".");
    const record: wire.Record = .{
        .owner = 0,
        .kind = .opt,
        .class = value.payload_bytes,
        .ttl_s = (@as(u32, value.extended_rcode) << wire.edns_rcode_shift) |
            (@as(u32, value.version) << wire.edns_version_shift) | value.flags,
        .data_start = 0,
        .data_end = 0,
        .section = .additional,
    };
    const offset = try encoder.beginRecord(&root, &record);
    try encoder.bytes(value.options);
    encoder.endRecord(offset);
}

/// Responses retain only COOKIE; upstream queries retain every validated option.
pub fn responseOptions(packet: *const wire.Packet, target: []u8) wire.Error![]const u8 {
    const index = packet.opt orelse return target[0..0];
    const record = &packet.records[index];
    var iterator: wire.Options = .{ .bytes = packet.bytes[record.data_start..record.data_end] };
    while (try iterator.next()) |option| {
        if (option.code != wire.cookie_option_code) continue;
        if (target.len < option.data.len + 4) return error.NoSpace;
        wire.put(u16, target[0..2], wire.cookie_option_code);
        wire.put(u16, target[2..4], @intCast(option.data.len));
        @memcpy(target[4..][0..option.data.len], option.data);
        return target[0 .. option.data.len + 4];
    }
    return target[0..0];
}

pub fn upstreamEdns(packet: *const wire.Packet) Edns {
    const index = packet.opt orelse return .{ .payload_bytes = wire.upstream_payload_bytes };
    const record = &packet.records[index];
    return .{
        .payload_bytes = wire.upstream_payload_bytes,
        .flags = @as(u16, @truncate(record.ttl_s)) & wire.edns_dnssec_ok,
        .options = packet.bytes[record.data_start..record.data_end],
    };
}

comptime {
    if (builtin.is_test) _ = WireTestsRewrite;
}

const WireTestsRewrite = struct {
    const testing = std.testing;

    const cookie = "\x00\x0a\x00\x08abcdefgh";
    const unknown = "\xfd\xe8\x00\x03\xc0\x0c\xff";

    // RFC 6891 §6.1 and RFC 7873 §4: preserve options, metadata and client COOKIE.
    test "EDNS round trip and client envelope replacement" {
        var bytes: [65535]u8 = undefined;
        var encoder: wire.Encoder = undefined;
        try encoder.init(&bytes, &.{ .id = 123, .bits = 0x8180 });
        var name: wire.Name = undefined;
        try name.fromText("server.example.");
        try encoder.question(&name, .aaaa, 3);
        const client_edns: wire.rewrite.Edns = .{
            .payload_bytes = 4096,
            .extended_rcode = 1,
            .version = 1,
            .flags = 0x8000,
            .options = cookie ++ unknown,
        };
        try wire.rewrite.writeOpt(&encoder, &client_edns);
        var packet: wire.Packet = undefined;
        try packet.parse(try encoder.finish());
        var workspace: wire.rewrite.Workspace = undefined;
        var output: [65535]u8 = undefined;
        try testing.expectEqualSlices(
            u8,
            packet.bytes,
            try workspace.rewrite(&packet, &output, &.{}),
        );
        const upstream = wire.rewrite.upstreamEdns(&packet);
        try testing.expectEqual(1232, upstream.payload_bytes);
        try testing.expectEqual(0x8000, upstream.flags);
        try testing.expectEqual(0, upstream.version);
        try testing.expectEqualSlices(u8, cookie ++ unknown, upstream.options);
        var options: [44]u8 = undefined;
        const client: wire.rewrite.Edns = .{
            .payload_bytes = 1232,
            .options = try wire.rewrite.responseOptions(&packet, &options),
        };
        try testing.expectEqualSlices(u8, cookie, client.options);
        try name.fromText("Client.Example.");
        const result = try workspace.rewrite(&packet, &output, &.{
            .id = 456,
            .question = .{ .name = &name, .kind = .a, .class = 3 },
            .opt = .{ .replace = &client },
        });
        var decoded: wire.Packet = undefined;
        try decoded.parse(result);
        try testing.expectEqual(456, decoded.header.id);
        try testing.expectEqual(1232, decoded.records[decoded.opt.?].class);
        try testing.expectEqual(0, decoded.records[decoded.opt.?].ttl_s);
        var cursor: usize = 12;
        const question = try decoded.readQuestion(&cursor);
        try testing.expectEqual(3, question.class);
        var restored: wire.Name = undefined;
        try decoded.name(&restored, question.name);
        try testing.expectEqualSlices(u8, name.wire(), restored.wire());
        try decoded.parse(try workspace.rewrite(&packet, &output, &.{ .opt = .omit }));
        try testing.expectEqual(null, decoded.opt);
    }

    // RFC 6891 §6.1.1 and RFC 7873 §4: invalid or repeated OPT/COOKIE is FORMERR.
    test "OPT owner section duplicates and COOKIE lengths reject" {
        for ([_]usize{ 0, 7, 9, 15, 41 }) |length| {
            const data: [41]u8 = @splat(0);
            try testing.expectError(error.InvalidCookie, wire.validateCookie(data[0..length]));
        }
        for ([_]usize{ 8, 16, 40 }) |length| {
            const data: [40]u8 = @splat(0);
            try wire.validateCookie(data[0..length]);
        }
        var builder: fixture.Builder = undefined;
        var packet: wire.Packet = undefined;
        builder.init();
        builder.record(&.{0}, 41, .answer, &.{});
        try testing.expectError(error.InvalidOpt, packet.parse(try builder.finish()));
        builder.init();
        builder.record("\x01x\x00", 41, .additional, &.{});
        try testing.expectError(error.InvalidOpt, packet.parse(try builder.finish()));
        builder.init();
        builder.record(&.{0}, 41, .additional, cookie ++ cookie);
        try testing.expectError(error.InvalidCookie, packet.parse(try builder.finish()));
        builder.init();
        builder.record(&.{0}, 41, .additional, &.{});
        builder.record(&.{0}, 41, .additional, &.{});
        try testing.expectError(error.DuplicateOpt, packet.parse(try builder.finish()));
        builder.init();
        builder.record(&.{0}, 41, .additional, &.{ 0, 10, 0, 8 });
        try testing.expectError(error.InvalidOption, packet.parse(try builder.finish()));
    }

    // RFC 2181 §9 and SPEC §3.9: keep whole RRsets, the question and required OPT.
    test "UDP truncation removes interleaved partial RRsets and reserves OPT" {
        var builder: fixture.Builder = undefined;
        builder.init();
        builder.question("\x01x\x00", 65400, 1);
        const data: [160]u8 = @splat(42);
        builder.record("\xc0\x0c", 65400, .answer, &data);
        builder.record("\x01y\x00", 65400, .answer, &data);
        builder.record("\xc0\x0c", 65400, .answer, &data);
        var packet: wire.Packet = undefined;
        try packet.parse(try builder.finish());
        var workspace: wire.rewrite.Workspace = undefined;
        var output: [65535]u8 = undefined;
        const opt: wire.rewrite.Edns = .{ .payload_bytes = 512, .options = cookie };
        const result = try workspace.rewrite(&packet, &output, &.{
            .limit = .{ .udp = 512 },
            .opt = .{ .replace = &opt },
        });
        try testing.expect(result.len <= 512);
        var decoded: wire.Packet = undefined;
        try decoded.parse(result);
        try testing.expect(decoded.header.has(.truncated));
        try testing.expectEqual(0, decoded.header.counts[1]);
        try testing.expectEqual(1, decoded.header.counts[0]);
        try testing.expectEqual(1, decoded.header.counts[3]);
        const complete = try workspace.rewrite(&packet, &output, &.{});
        try decoded.parse(complete);
        try testing.expectEqual(3, decoded.header.counts[1]);
        try testing.expect(!decoded.header.has(.truncated));
    }

    // SPEC §3.9: order changes cannot duplicate records or cross DNS sections.
    test "invalid permutations and small output fail explicitly" {
        var builder: fixture.Builder = undefined;
        builder.init();
        builder.record(&.{0}, 65400, .answer, &.{});
        builder.record(&.{0}, 65400, .additional, &.{});
        var packet: wire.Packet = undefined;
        try packet.parse(try builder.finish());
        var output: [65535]u8 = undefined;
        var workspace: wire.rewrite.Workspace = undefined;
        for ([_][]const u16{ &.{0}, &.{ 0, 0 }, &.{ 0, 2 }, &.{ 1, 0 } }) |order| {
            try testing.expectError(
                error.InvalidOrder,
                workspace.rewrite(&packet, &output, &.{ .order = order }),
            );
        }
        try testing.expectError(error.NoSpace, workspace.rewrite(&packet, output[0..11], &.{}));
        try testing.expectError(error.NoSpace, workspace.rewrite(&packet, output[0..12], &.{}));
    }
};
