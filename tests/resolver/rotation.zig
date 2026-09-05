const std = @import("std");
const f = @import("fixture.zig");
const testing = f.testing;
const resolver = f.resolver;
const rotation = resolver.rotation;
const wire = f.wire;

fn add(encoder: *wire.Encoder, kind: u16, section: wire.Section, marker: u8) !void {
    var name: wire.Name = undefined;
    try name.fromText("alias.example.");
    const value: wire.Record = .{
        .owner = 0,
        .kind = kind,
        .class = 1,
        .ttl_s = marker,
        .data_start = 0,
        .data_end = 0,
        .section = section,
    };
    const offset = try encoder.beginRecord(&name, &value);
    switch (kind) {
        1 => try encoder.bytes(&.{ 192, 0, 2, marker }),
        28 => try encoder.bytes(&(.{0} ** 15 ++ .{marker})),
        5, 2 => try encoder.name(&name, .allowed),
        15 => {
            try encoder.number(u16, marker);
            try encoder.name(&name, .allowed);
        },
        else => try encoder.bytes(&.{ 0xc0, 0x0c, marker }),
    }
    encoder.endRecord(offset);
}

fn init(fixture: *f.Fixture) !void {
    try fixture.init("example.", 1, 1);
    fixture.encoder.header.bits = 0x8520;
    for ([_]u16{ 28, 15, 65280, 5, 1, 15, 1, 5, 65281 }) |kind| {
        try add(&fixture.encoder, kind, .answer, @intCast(fixture.encoder.header.counts[1] + 1));
    }
    try add(&fixture.encoder, 2, .authority, 31);
    try add(&fixture.encoder, 1, .additional, 32);
    const edns: wire.rewrite.Edns = .{ .payload_bytes = 1232 };
    try wire.rewrite.writeOpt(&fixture.encoder, &edns);
    try fixture.query.parse(try fixture.encoder.finish());
}

// SPEC §3.8: stable CNAME/rest groups precede separately shuffled address/MX groups.
test "rotation composition is a complete permutation with unchanged trailing sections" {
    var fixture: f.Fixture = undefined;
    try init(&fixture);
    var order: [wire.records_max]u16 = undefined;
    var random = std.Random.DefaultPrng.init(42);
    var seen_addresses = std.StaticBitSet(9).initEmpty();
    var seen_mail = std.StaticBitSet(9).initEmpty();
    for (0..64) |_| {
        rotation.makeOrder(&order, &fixture.query, .forward, .rotate, random.random());
        try testing.expectEqualSlices(u16, &.{ 3, 7, 2, 8 }, order[0..4]);
        var seen = std.StaticBitSet(wire.records_max).initEmpty();
        for (order[0..fixture.query.record_count]) |index| {
            try testing.expect(!seen.isSet(index));
            seen.set(index);
        }
        try testing.expectEqual(@as(usize, fixture.query.record_count), seen.count());
        for (order[4..7]) |index| switch (fixture.query.records[index].kind) {
            1, 28 => {},
            else => return error.TestExpectedEqual,
        };
        for (order[7..9]) |index| {
            try testing.expectEqual(@as(u16, 15), fixture.query.records[index].kind);
        }
        try testing.expectEqualSlices(u16, &.{ 9, 10, 11 }, order[9..12]);
        seen_addresses.set(order[4]);
        seen_mail.set(order[7]);
    }
    try testing.expectEqual(@as(usize, 3), seen_addresses.count());
    try testing.expectEqual(@as(usize, 2), seen_mail.count());
}

// SPEC §3.2, §3.8: disabled/non-NOERROR/RFC6761/NODATA never rotate or consume random state.
test "rotation bypasses excluded sources errors and disabled mode" {
    var fixture: f.Fixture = undefined;
    try init(&fixture);
    var order: [wire.records_max]u16 = undefined;
    var random = std.Random.DefaultPrng.init(42);
    const initial = random;
    for ([_]rotation.Source{ .rfc6761, .nodata }) |source| {
        rotation.makeOrder(&order, &fixture.query, source, .rotate, random.random());
        try identity(order[0..fixture.query.record_count]);
    }
    rotation.makeOrder(&order, &fixture.query, .forward, .fixed, random.random());
    try identity(order[0..fixture.query.record_count]);
    fixture.query.header.bits |= 3;
    rotation.makeOrder(&order, &fixture.query, .forward, .rotate, random.random());
    try identity(order[0..fixture.query.record_count]);
    fixture.query.header.bits &= ~@as(u16, 15);
    fixture.query.records[fixture.query.opt.?].ttl_s = 1 << 24;
    rotation.makeOrder(&order, &fixture.query, .cache, .rotate, random.random());
    try identity(order[0..fixture.query.record_count]);
    try testing.expectEqualDeep(initial, random);
}

fn identity(order: []const u16) !void {
    for (order, 0..) |index, position| try testing.expectEqual(position, index);
}

// SPEC §3.2, §3.8–3.9; RFC 1035 §4.1.4: compressed owner/RDATA survive movement.
test "rotation rewrites compressed names opaque bytes and preserves flags" {
    var fixture: f.Fixture = undefined;
    try init(&fixture);
    var workspace: rotation.Workspace = undefined;
    var random = std.Random.DefaultPrng.init(42);
    const original = fixture.query.header.bits;
    for ([_]rotation.Source{ .forward, .cache, .hosts }) |source| {
        const bytes = try workspace.finish(
            &fixture.query,
            &fixture.output,
            &.{},
            source,
            .rotate,
            random.random(),
        );
        try fixture.response.parse(bytes);
        const expected = if (source == .forward) original | 0x80 else original;
        try testing.expectEqual(expected, fixture.response.header.bits);
        try testing.expectEqual(original, fixture.query.header.bits);
        try testing.expectEqual(fixture.query.record_count, fixture.response.record_count);
        for (workspace.order[0..fixture.query.record_count], 0..) |index, position| {
            try equivalent(
                &fixture.query,
                &fixture.query.records[index],
                &fixture.response,
                &fixture.response.records[position],
            );
        }
    }
    try testing.expect(rotation.Source.forward.cacheable());
    try testing.expect(!rotation.Source.cache.cacheable());
}

fn equivalent(
    source: *wire.Packet,
    left: *const wire.Record,
    target: *wire.Packet,
    right: *const wire.Record,
) !void {
    try testing.expectEqual(left.kind, right.kind);
    try testing.expectEqual(left.class, right.class);
    try testing.expectEqual(left.ttl_s, right.ttl_s);
    try testing.expectEqual(left.section, right.section);
    var source_name: wire.Name = undefined;
    var target_name: wire.Name = undefined;
    try source.name(&source_name, left.owner);
    try target.name(&target_name, right.owner);
    try testing.expectEqualSlices(u8, source_name.wire(), target_name.wire());
    var source_parts: wire.rdata.Parts = undefined;
    var target_parts: wire.rdata.Parts = undefined;
    try wire.rdata.parse(&source_parts, source, left);
    try wire.rdata.parse(&target_parts, target, right);
    try testing.expectEqual(source_parts.count, target_parts.count);
    const source_items = source_parts.items[0..source_parts.count];
    const target_items = target_parts.items[0..target_parts.count];
    for (source_items, target_items) |a, b| {
        switch (a) {
            .bytes => |range| try testing.expectEqualSlices(
                u8,
                source.bytes[range.start..range.end],
                target.bytes[b.bytes.start..b.bytes.end],
            ),
            .name => |reference| {
                try source.name(&source_name, reference.offset);
                try target.name(&target_name, b.name.offset);
                try testing.expectEqualSlices(u8, source_name.wire(), target_name.wire());
            },
        }
    }
}

// SPEC §3.8: cache hits rotate afresh rather than retaining one frozen permutation.
test "cache hits reshuffle on each response and zero answers are safe" {
    var fixture: f.Fixture = undefined;
    try init(&fixture);
    var workspace: rotation.Workspace = undefined;
    var random = std.Random.DefaultPrng.init(42);
    var seen = std.StaticBitSet(9).initEmpty();
    for (0..64) |_| {
        _ = try workspace.finish(
            &fixture.query,
            &fixture.output,
            &.{},
            .cache,
            .rotate,
            random.random(),
        );
        seen.set(workspace.order[4]);
    }
    try testing.expectEqual(@as(usize, 3), seen.count());
    try fixture.init("empty.", 1, 1);
    fixture.query.header.bits |= 0x8000;
    const bytes = try workspace.finish(
        &fixture.query,
        &fixture.output,
        &.{},
        .hosts,
        .rotate,
        random.random(),
    );
    try fixture.response.parse(bytes);
    try testing.expectEqual(@as(u16, 0), fixture.response.record_count);
}

// SPEC §3.9: rewrite failure is explicit and cannot leak temporary forward flags.
test "rotation short output failure restores borrowed packet flags" {
    var fixture: f.Fixture = undefined;
    try init(&fixture);
    var workspace: rotation.Workspace = undefined;
    var random = std.Random.DefaultPrng.init(42);
    const bits = fixture.query.header.bits;
    try testing.expectError(error.NoSpace, workspace.finish(
        &fixture.query,
        fixture.output[0..12],
        &.{},
        .forward,
        .rotate,
        random.random(),
    ));
    try testing.expectEqual(bits, fixture.query.header.bits);
}

// SPEC §3.2: forward sets only RA; cache preserves AA, RA, and all other stored flags.
test "forward and cache flag matrix" {
    var fixture: f.Fixture = undefined;
    try init(&fixture);
    var workspace: rotation.Workspace = undefined;
    var random = std.Random.DefaultPrng.init(42);
    for ([_]u16{ 0x8100, 0x8500, 0x8180, 0x85a0 }) |bits| {
        const stored = rotation.Source.forward.responseBits(bits);
        try testing.expectEqual(bits | 0x80, stored);
        try testing.expectEqual(stored, rotation.Source.cache.responseBits(stored));
        fixture.query.header.bits = bits;
        for ([_]rotation.Source{ .forward, .cache }) |source| {
            const bytes = try workspace.finish(
                &fixture.query,
                &fixture.output,
                &.{},
                source,
                .fixed,
                random.random(),
            );
            try fixture.response.parse(bytes);
            try testing.expectEqual(
                if (source == .forward) bits | 0x80 else bits,
                fixture.response.header.bits,
            );
            try testing.expectEqual(bits, fixture.query.header.bits);
        }
    }
}
