//! Synchronous pipeline seams. The runtime routes first, then calls beforeCache;
//! only its miss permits cache lookup, and only a cache miss permits afterCache.
//! Output must not overlap the borrowed request packet or encoder workspace.
pub const wire = @import("wire.zig");
pub const config = @import("config.zig");
pub const hosts = @import("hosts.zig");
pub const rotation = @import("rotation.zig");
pub const Source = rotation.Source;
const std = @import("std");

pub const Request = struct {
    packet: *const wire.Packet,
    name: wire.Name,
    kind: u16,
    class: u16,

    /// Accept only packets already admitted by wire.query.
    pub fn init(self: *Request, packet: *wire.Packet) wire.Error!void {
        std.debug.assert(packet.header.counts[0] == 1);
        std.debug.assert(packet.header.opcode() == 0);
        std.debug.assert(!packet.header.has(.response));
        var cursor: usize = 12;
        const question = try packet.readQuestion(&cursor);
        self.packet = packet;
        self.kind = question.kind;
        self.class = question.class;
        try packet.name(&self.name, question.name);
    }
};
pub const Answer = struct { bytes: []const u8, source: Source };
const Local = enum { loopback, reverse, empty };

/// A returned answer bypasses cache, NODATA, hosts, forward, and rotation.
/// null means the runtime must try its per-zone cache next.
pub fn beforeCache(
    request: *const Request,
    encoder: *wire.Encoder,
    output: []u8,
) wire.Error!?Answer {
    const local = covered(&request.name) orelse return null;
    try start(request, encoder, output);
    switch (local) {
        .loopback => switch (request.kind) {
            1 => try address(encoder, &request.name, 1, &.{ 127, 0, 0, 1 }),
            28 => try address(encoder, &request.name, 28, &(.{0} ** 15 ++ .{1})),
            else => {},
        },
        .reverse => {
            if (request.kind == 12) {
                const offset = try record(encoder, &request.name, 12, 30);
                var localhost: wire.Name = undefined;
                localhost.fromText("localhost.") catch unreachable;
                try encoder.name(&localhost, .allowed);
                encoder.endRecord(offset);
            }
        },
        .empty => {},
    }
    const answer = try finish(request, encoder, .rfc6761);
    return answer;
}

/// Invoke only after beforeCache and the cache both miss. null means forward.
/// NODATA and hosts answers never enter the cache. Only hosts may rotate.
pub fn afterCache(
    request: *const Request,
    zone: *const config.Zone,
    table: ?*const hosts.Table,
    encoder: *wire.Encoder,
    output: []u8,
) wire.Error!?Answer {
    return afterCacheInner(request, zone, table, encoder, output) catch |err| {
        if (err == error.NoSpace) {
            if (output.len >= wire.message_bytes_max) return error.RewriteTooLarge;
        }
        return err;
    };
}

fn afterCacheInner(
    request: *const Request,
    zone: *const config.Zone,
    table: ?*const hosts.Table,
    encoder: *wire.Encoder,
    output: []u8,
) wire.Error!?Answer {
    for (zone.nodata) |kind| {
        if (kind.code() != request.kind) continue;
        try start(request, encoder, output);
        const answer = try finish(request, encoder, .nodata);
        return answer;
    }
    const settings = zone.hosts orelse return null;
    if (request.class != 1) return null;
    const snapshot = table orelse return null;
    var count: u16 = 0;
    for (snapshot.entries()) |*entry| {
        if (!entry.matches(&request.name, request.kind)) continue;
        if (count == 0) try start(request, encoder, output);
        const offset = try record(encoder, &request.name, request.kind, settings.ttl);
        try entry.write(encoder, request.kind);
        encoder.endRecord(offset);
        count += 1;
    }
    if (count == 0) return null;
    const answer = try finish(request, encoder, .hosts);
    return answer;
}

fn start(request: *const Request, encoder: *wire.Encoder, output: []u8) wire.Error!void {
    // Echo RD/CD only. Synthetic data is authoritative, never authenticated or recursive.
    const header: wire.Header = .{
        .id = request.packet.header.id,
        .bits = (request.packet.header.bits & 0x0110) | 0x8400,
    };
    try encoder.init(output, &header);
    try encoder.question(&request.name, request.kind, request.class);
}

fn finish(request: *const Request, encoder: *wire.Encoder, source: Source) wire.Error!Answer {
    var cookie: [44]u8 = undefined;
    if (request.packet.opt) |index| {
        const options = try wire.rewrite.responseOptions(request.packet, &cookie);
        const edns: wire.rewrite.Edns = .{
            .payload_bytes = request.packet.records[index].class,
            .options = options,
        };
        try wire.rewrite.writeOpt(encoder, &edns);
    }
    return .{ .bytes = try encoder.finish(), .source = source };
}

fn record(
    encoder: *wire.Encoder,
    name: *const wire.Name,
    kind: u16,
    ttl_s: u32,
) wire.Error!usize {
    const value: wire.Record = .{
        .owner = 0,
        .kind = kind,
        .class = 1,
        .ttl_s = ttl_s,
        .data_start = 0,
        .data_end = 0,
        .section = .answer,
    };
    return encoder.beginRecord(name, &value);
}

fn address(
    encoder: *wire.Encoder,
    name: *const wire.Name,
    kind: u16,
    bytes: []const u8,
) wire.Error!void {
    const offset = try record(encoder, name, kind, 30);
    try encoder.bytes(bytes);
    encoder.endRecord(offset);
}

fn covered(name: *const wire.Name) ?Local {
    var suffix: wire.Name = undefined;
    suffix.fromText("1.0.0.127.in-addr.arpa.") catch unreachable;
    if (name.equal(&suffix)) return .reverse;
    const zones = .{ "localhost.", "0.in-addr.arpa.", "127.in-addr.arpa.", "255.in-addr.arpa." };
    inline for (zones, 0..) |zone, index| {
        suffix.fromText(zone) catch unreachable;
        var offset: usize = 0;
        while (offset < name.length) {
            if (std.ascii.eqlIgnoreCase(name.wire()[offset..], suffix.wire())) {
                return if (index == 0) .loopback else .empty;
            }
            offset += @as(usize, name.bytes[offset]) + 1;
        }
    }
    return null;
}
