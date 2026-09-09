const wire = @import("../wire.zig");
const ArrayBuffer = @import("../array_buffer.zig").ArrayBuffer;

pub const Edns = struct {
    payload_bytes: u16,
    extended_rcode: u8 = 0,
    version: u8 = 0,
    flags: u16 = 0,
    options: []const u8 = &.{},
};
pub const OptPolicy = union(enum) { preserve, omit, replace: *const Edns };
pub const Limit = union(enum) { tcp, udp: u16 };
pub const Question = struct { name: *const wire.Name, kind: u16, class: u16 };
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
        const reserve: usize = if (opt) |value| 11 + value.options.len else 0;
        const limit: usize = switch (settings.limit) {
            .tcp => wire.message_bytes_max,
            .udp => |size| @max(512, size),
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
            if (record.kind == 41) continue;
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
            var cursor: usize = 12;
            for (0..packet.header.counts[0]) |_| {
                var name: wire.Name = undefined;
                const question = try packet.readQuestionInto(&name, &cursor);
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
    return source.equal(&target);
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
                .extended_rcode = @truncate(record.ttl_s >> 24),
                .version = @truncate(record.ttl_s >> 16),
                .flags = @truncate(record.ttl_s),
                .options = packet.bytes[record.data_start..record.data_end],
            };
        },
    }
}

pub fn validateOptions(options: []const u8) wire.Error!void {
    if (options.len > 65524) return error.InvalidOption;
    var iterator: wire.Options = .{ .bytes = options };
    var cookie: ?[]const u8 = null;
    while (try iterator.next()) |option| {
        if (option.code == 10) {
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
        .kind = 41,
        .class = value.payload_bytes,
        .ttl_s = (@as(u32, value.extended_rcode) << 24) |
            (@as(u32, value.version) << 16) | value.flags,
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
        if (option.code != 10) continue;
        if (target.len < option.data.len + 4) return error.NoSpace;
        wire.put(u16, target[0..2], 10);
        wire.put(u16, target[2..4], @intCast(option.data.len));
        @memcpy(target[4..][0..option.data.len], option.data);
        return target[0 .. option.data.len + 4];
    }
    return target[0..0];
}

pub fn upstreamEdns(packet: *const wire.Packet) Edns {
    const index = packet.opt orelse return .{ .payload_bytes = 1232 };
    const record = &packet.records[index];
    return .{
        .payload_bytes = 1232,
        .flags = @as(u16, @truncate(record.ttl_s)) & 0x8000,
        .options = packet.bytes[record.data_start..record.data_end],
    };
}
