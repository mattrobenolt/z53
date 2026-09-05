const std = @import("std");
const wire = @import("wire");
const fixture = @import("wire/fixture.zig");
const equivalent = @import("wire/equivalent.zig").equivalent;

// SPEC §9.3: bounded Smith storage follows the pinned ztls fuzz pattern.
test "fuzz DNS decoder and safe rewrites" {
    try std.testing.fuzz({}, fuzzOne, .{ .corpus = &.{ "\x00" ** 12, "\xff" ** 32 } });
}

// SPEC §9.3 and RFC 3597 §4: mutate structured packets to reach RDATA and movement.
test "fuzz structured DNS record relocation" {
    try std.testing.fuzz({}, fuzzStructured, .{ .corpus = &.{ "", "\x00" ** 32 } });
}

// Unexpected outcomes panic: they remain visible with fuzz error tracing disabled (#1).
fn fuzzOne(_: void, smith: *std.testing.Smith) error{}!void {
    var storage: [65536]u8 = undefined;
    const length = smith.slice(&storage);
    check(storage[0..length]);
}

fn fuzzStructured(_: void, smith: *std.testing.Smith) error{}!void {
    var mutations: [64]u8 = undefined;
    const length = smith.slice(&mutations);
    var builder: fixture.Builder = undefined;
    builder.init();
    builder.question("\x01x\x07example\x00", 1, 1);
    builder.record("\xc0\x0c", 5, .answer, "\x06target\xc0\x0e");
    builder.record("\xc0\x0c", 15, .answer, "\x00\x0a\xc0\x0c");
    builder.record("\xc0\x0c", 65400, .answer, mutations[0..length]);
    const target: u16 = @intCast(builder.cursor + 14);
    builder.record("\xc0\x0c", 64, .answer, "\x00\x01\x06target\x07example\x00");
    var owner: [2]u8 = undefined;
    wire.put(u16, &owner, 0xc000 | target);
    builder.record(&owner, 1, .answer, &.{ 127, 0, 0, 1 });
    builder.record("\xc0\x0c", 6, .authority, "\xc0\x0c\xc0\x0c" ++ "\x00" ** 20);
    const bytes = builder.finish() catch @panic("fixture header failed");
    if (length >= 3) {
        const offset: usize = wire.integer(u16, mutations[0..2]);
        bytes[offset % bytes.len] = mutations[2];
    }
    check(bytes);
}

fn check(bytes: []const u8) void {
    var packet: wire.Packet = undefined;
    packet.parse(bytes) catch {
        _ = wire.malformed(bytes);
        return;
    };
    var order: [wire.records_max]u16 = undefined;
    var start: usize = 0;
    for (0..packet.record_count) |index| {
        order[index] = @intCast(index);
        if (packet.records[index].section != packet.records[start].section) {
            std.mem.reverse(u16, order[start..index]);
            start = index;
        }
    }
    std.mem.reverse(u16, order[start..packet.record_count]);
    var workspace: wire.rewrite.Workspace = undefined;
    var output: [65535]u8 = undefined;
    const result = workspace.rewrite(&packet, &output, &.{
        .order = order[0..packet.record_count],
    }) catch |err| switch (err) {
        error.RewriteTooLarge => return,
        else => @panic(@errorName(err)),
    };
    var decoded: wire.Packet = undefined;
    decoded.parse(result) catch |err| @panic(@errorName(err));
    std.testing.expectEqual(packet.header, decoded.header) catch @panic("header changed");
    std.testing.expectEqual(packet.record_count, decoded.record_count) catch
        @panic("record count changed");
    var target: usize = 0;
    for (order[0..packet.record_count]) |index| {
        const record = &packet.records[index];
        const position = if (record.kind == 41) decoded.opt.? else target;
        equivalent(&packet, record, &decoded, &decoded.records[position]) catch
            @panic("record changed during relocation");
        if (record.kind != 41) target += 1;
    }
    checkQuestions(&packet, &decoded);
}

fn checkQuestions(source: *wire.Packet, target: *wire.Packet) void {
    var source_cursor: usize = 12;
    var target_cursor: usize = 12;
    for (0..source.header.counts[0]) |_| {
        const left = source.readQuestion(&source_cursor) catch @panic("source question invalid");
        const right = target.readQuestion(&target_cursor) catch @panic("target question invalid");
        var source_name: wire.Name = undefined;
        var target_name: wire.Name = undefined;
        source.name(&source_name, left.name) catch @panic("source name invalid");
        target.name(&target_name, right.name) catch @panic("target name invalid");
        std.testing.expectEqual(left.kind, right.kind) catch @panic("question type changed");
        std.testing.expectEqual(left.class, right.class) catch @panic("question class changed");
        std.testing.expectEqualSlices(u8, source_name.wire(), target_name.wire()) catch
            @panic("question name changed");
    }
}
