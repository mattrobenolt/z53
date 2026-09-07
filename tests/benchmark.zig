//! SPEC §§3.1, 3.2, 3.7, 9.4: bounded DNS baselines through the pinned helper (#1).
const std = @import("std");
const benchmark = @import("benchmark");
const pipeline = @import("pipeline").pipeline;
const wire = pipeline.wire;
const config = pipeline.resolver.config;
const scaling = @import("benchmark_cache.zig");
const Mode = enum { smoke, baseline, wire, route, index, cache, churn, profile, layout };
const cases = [_]benchmark.Spec{
    .{ .name = "WireDecodeAResponse", .func = decode },
    .{ .name = "LongestSuffix64", .func = route },
    .{ .name = "CacheHitPipeline1", .func = cacheOne },
};

pub fn main(init: std.process.Init) !void {
    var arguments = try init.minimal.args.iterateAllocator(init.gpa);
    defer arguments.deinit();
    _ = arguments.skip();
    const mode = std.meta.stringToEnum(Mode, arguments.next() orelse "baseline") orelse
        return error.InvalidMode;
    if (arguments.next() != null) return error.UnexpectedArgument;
    if (mode == .profile) return scaling.profile(&init);
    if (mode == .layout) return scaling.layout(init.gpa);
    const selected: []const benchmark.Spec = switch (mode) {
        .smoke, .baseline => &cases,
        .wire => cases[0..1],
        .route => cases[1..2],
        .index, .cache, .churn => &.{},
        .profile, .layout => unreachable,
    };
    if (!try benchmark.runBenchmarks(init.gpa, selected, .{
        .io = init.io,
        .benchtime = .{ .count = if (mode == .smoke) 8 else 100000 },
        .count = if (mode == .smoke) 1 else 3,
        .benchmem = true,
    })) return error.BenchmarkFailed;
    inline for (comptime std.meta.tags(scaling.Mode)) |group| {
        switch (mode) {
            .baseline => try scaling.run(&init, group, .trials),
            .smoke => try scaling.run(&init, group, .short),
            else => if (std.mem.eql(u8, @tagName(mode), @tagName(group)))
                try scaling.run(&init, group, .trials),
        }
    }
}

fn message(output: []u8, index: u16, kind: enum { query, response }) ![]const u8 {
    var text: [64]u8 = undefined;
    var name: wire.Name = undefined;
    try name.fromText(try std.fmt.bufPrint(&text, "host{d}.bench.example.", .{index}));
    var encoder: wire.Encoder = undefined;
    try encoder.init(output, &.{ .id = index, .bits = if (kind == .query) 0x100 else 0x8180 });
    try encoder.question(&name, 1, 1);
    if (kind == .response) {
        const record: wire.Record = .{
            .owner = 0,
            .kind = 1,
            .class = 1,
            .ttl_s = 300,
            .data_start = 0,
            .data_end = 0,
            .section = .answer,
        };
        const offset = try encoder.beginRecord(&name, &record);
        try encoder.bytes(&.{ 192, 0, 2, 1 });
        encoder.endRecord(offset);
    }
    return encoder.finish();
}

fn decode(timer: *benchmark.B) !void {
    const packet = try timer.allocator.create(wire.Packet);
    defer timer.allocator.destroy(packet);
    var input: [512]u8 = undefined;
    const bytes = try message(&input, 42, .response);
    while (try timer.loop()) {
        try packet.parse(benchmark.blackBox(bytes));
        benchmark.keepAlive(packet);
    }
    if (packet.header.id != 42) return error.WrongIdentifier;
    if (packet.header.counts[1] != 1) return error.WrongAnswerCount;
}

fn route(timer: *benchmark.B) !void {
    var zones: [64]config.Zone = undefined;
    var suffixes: [64][64]u8 = undefined;
    const upstreams = [_]config.Upstream{.{ .address = "127.0.0.1:9" }};
    for (&zones, &suffixes, 0..) |*zone, *suffix, index| {
        zone.* = .{
            .suffix = try std.fmt.bufPrint(suffix, "zone{d}.example.", .{index}),
            .upstreams = &upstreams,
            .cache = null,
        };
    }
    zones[0].suffix = ".";
    zones[1].suffix = "example.";
    const settings: config.Config = .{ .zones = &zones };
    var names: [2]wire.Name = undefined;
    try names[0].fromText("host.ZONE63.Example.");
    try names[1].fromText("other.zone62.example.");
    var index: u32 = 0;
    var selected: ?u16 = null;
    while (try timer.loop()) {
        selected = config.route(benchmark.blackBox(&settings), &names[index % 2]);
        benchmark.keepAlive(selected);
        index += 1;
    }
    if (selected != 62) return error.WrongZone;
}

fn cacheOne(timer: *benchmark.B) !void {
    try cacheHit(timer, 1);
}

fn cacheHit(timer: *benchmark.B, entries: u16) !void {
    const service = try timer.allocator.create(pipeline.Pipeline);
    defer timer.allocator.destroy(service);
    const upstreams = [_]config.Upstream{.{ .address = "127.0.0.1:9" }};
    var zones = [_]config.Zone{.{
        .suffix = ".",
        .upstreams = &upstreams,
        .cache = .{ .capacity = entries },
    }};
    const settings: config.Config = .{ .zones = &zones };
    try service.init(timer.allocator, timer.timer.io, &settings);
    defer service.deinit();
    var input: [512]u8 = undefined;
    var response: [512]u8 = undefined;
    var output: [512]u8 = undefined;
    for (0..entries) |index| {
        const request = try message(&input, @intCast(index), .query);
        const completion: pipeline.Completion = .{
            .response = try message(&response, @intCast(index), .response),
        };
        const admitted = try service.complete(
            request,
            &output,
            .{ .udp = .ipv4 },
            100,
            &completion,
        );
        if (admitted.source != .forward) return error.WrongSource;
    }
    // The last occupied slot exercises the complete bounded scan, not an empty cache.
    const bytes = try message(&input, entries - 1, .query);
    var result: ?pipeline.resolver.Answer = null;
    while (try timer.loop()) {
        result = try service.answer(benchmark.blackBox(bytes), &output, .{ .udp = .ipv4 }, 101);
        benchmark.keepAlive(output[0..result.?.bytes.len]);
        benchmark.keepAlive(result.?.source);
    }
    if (result.?.source != .cache) return error.WrongSource;
    const header = try wire.Header.decode(result.?.bytes);
    if (header.id != entries - 1) return error.WrongIdentifier;
    if (header.counts[1] != 1) return error.WrongAnswerCount;
    if (header.bits & 15 != 0) return error.WrongRcode;
}
