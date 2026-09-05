//! Reorder views, never raw compressed records. Rewriting relocates every known name.
const std = @import("std");
const wire = @import("wire.zig");

pub const Source = enum {
    rfc6761,
    nodata,
    hosts,
    cache,
    stale,
    servfail,
    forward,

    pub fn cacheable(self: Source) bool {
        // Terminal transport failures use Cache.terminalFailure, not generic insertion.
        return self == .forward;
    }

    /// Normalize forward flags before cache insertion as well as client delivery.
    pub fn responseBits(self: Source, bits: u16) u16 {
        return if (self == .forward) bits | @intFromEnum(wire.Flag.recursion_available) else bits;
    }

    pub fn rotatable(self: Source) bool {
        return switch (self) {
            .hosts, .cache, .stale, .forward => true,
            .rfc6761, .nodata, .servfail => false,
        };
    }
};
pub const Mode = enum { fixed, rotate };
const Group = enum { cname, other, address, mail };

pub const Workspace = struct {
    order: [wire.records_max]u16,
    rewrite: wire.rewrite.Workspace,

    /// Original packet and client options remain immutable; output must not alias them.
    /// This stage owns record order and replaces settings.order, even in fixed mode.
    pub fn finish(
        self: *Workspace,
        packet: *wire.Packet,
        output: []u8,
        settings: *const wire.rewrite.Settings,
        source: Source,
        mode: Mode,
        random: std.Random,
    ) wire.Error![]const u8 {
        makeOrder(&self.order, packet, source, mode, random);
        var applied = settings.*;
        applied.order = self.order[0..packet.record_count];
        const bits = packet.header.bits;
        defer packet.header.bits = bits;
        packet.header.bits = source.responseBits(bits);
        return self.rewrite.rewrite(packet, output, &applied);
    }
};

pub fn makeOrder(
    target: *[wire.records_max]u16,
    packet: *const wire.Packet,
    source: Source,
    mode: Mode,
    random: std.Random,
) void {
    for (target[0..packet.record_count], 0..) |*index, position| index.* = @intCast(position);
    if (mode == .fixed) return;
    if (!source.rotatable()) return;
    if (packet.header.bits & 15 != 0) return;
    if (packet.opt) |index| {
        if (packet.records[index].ttl_s >> 24 != 0) return;
    }
    var count: u16 = 0;
    for ([_]Group{ .cname, .other, .address, .mail }) |group| {
        const start = count;
        for (packet.records[0..packet.record_count], 0..) |*record, index| {
            if (record.section != .answer) continue;
            if (classify(record.kind) != group) continue;
            target[count] = @intCast(index);
            count += 1;
        }
        switch (group) {
            .address, .mail => random.shuffle(u16, target[start..count]),
            .cname, .other => {},
        }
    }
    std.debug.assert(count == packet.header.counts[1]);
    // Identity initialization retains authority/additional order, including OPT.
}

fn classify(kind: u16) Group {
    return switch (kind) {
        5 => .cname,
        1, 28 => .address,
        15 => .mail,
        else => .other,
    };
}
