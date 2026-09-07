//! SPEC §§1.3, 3.7, 9.4: cache scaling with identical timed production boundaries (#1).
const std = @import("std");
const benchmark = @import("benchmark");
const pipeline = @import("pipeline").pipeline;
const wire = pipeline.wire;
const resolver = pipeline.resolver;
const config = resolver.config;
const Bank = @TypeOf(@as(resolver.cache.Cache, undefined).positive);
const Key = @TypeOf(@as(resolver.cache.Entry, undefined).key);
const capacities = [_]u32{ 128, 1024, 10000, 100000 };
pub const Mode = enum { index, cache, churn };
const Case = enum {
    index_empty_miss,
    index_sparse_miss,
    index_full_miss,
    index_full_first,
    index_full_last,
    index_full_random,
    lookup_positive_last,
    lookup_denial_last,
    lookup_sparse_miss,
    pipeline_positive_last,
    insert_evict,
};

pub fn run(init: *const std.process.Init, mode: Mode, smoke: enum { short, trials }) !void {
    inline for (capacities) |capacity| {
        inline for (comptime std.meta.tags(Case)) |case| {
            const group: Mode = switch (case) {
                .index_empty_miss,
                .index_sparse_miss,
                .index_full_miss,
                .index_full_first,
                .index_full_last,
                .index_full_random,
                => .index,
                .insert_evict => .churn,
                else => .cache,
            };
            if (mode == group) {
                const iterations = if (case == .index_full_first)
                    100000
                else
                    @max(128, @divTrunc(10000000, capacity));
                const spec = [_]benchmark.Spec{.{
                    .name = comptime std.fmt.comptimePrint(
                        "{s}/capacity={d}",
                        .{ @tagName(case), capacity },
                    ),
                    .func = Runner(capacity, case).run,
                }};
                if (!try benchmark.runBenchmarks(init.gpa, &spec, .{
                    .io = init.io,
                    .emit_environment = false,
                    .benchmem = true,
                    .benchtime = .{ .count = if (smoke == .short) 8 else iterations },
                    .count = if (smoke == .short) 1 else 3,
                })) return error.BenchmarkFailed;
            }
        }
    }
}

const Fixture = struct {
    service: *pipeline.Pipeline,
    zones: [1]config.Zone,
    settings: config.Config,
    input: [512]u8,
    response: [512]u8,
    output: [512]u8,
    request: resolver.Request,
    keys: [256]Key,
    expected: [256]?u32,

    fn init(self: *Fixture, timer: *benchmark.B, capacity: u32, case: Case) !void {
        self.zones = .{.{
            .suffix = ".",
            .upstreams = &.{.{ .address = "127.0.0.1:9" }},
            .cache = .{ .capacity = capacity },
        }};
        self.settings = .{ .zones = &self.zones };
        self.service = try timer.allocator.create(pipeline.Pipeline);
        errdefer timer.allocator.destroy(self.service);
        try self.service.init(timer.allocator, timer.timer.io, &self.settings);
        errdefer self.service.deinit();
        const occupancy = switch (case) {
            .index_empty_miss => 0,
            .index_sparse_miss, .lookup_sparse_miss => capacity / 8,
            else => capacity,
        };
        // Direct seeding avoids quadratic setup. Every entry owns its packet and valid LRU links.
        try self.seed(
            timer.allocator,
            &self.service.zones[0].cache.positive,
            occupancy,
            0,
            .positive,
        );
        if (case == .lookup_denial_last) try self.seed(
            timer.allocator,
            &self.service.zones[0].cache.denial,
            capacity,
            capacity,
            .denial,
        );
        var random: std.Random.DefaultPrng = .init(822);
        for (&self.keys, &self.expected) |*key, *expected| {
            const index: u32 = switch (case) {
                .index_full_first => 0,
                .index_full_random => random.random().uintLessThan(u32, capacity),
                .index_empty_miss,
                .index_sparse_miss,
                .index_full_miss,
                .lookup_sparse_miss,
                => capacity,
                .lookup_denial_last => capacity * 2 - 1,
                else => capacity - 1,
            };
            try key.name.fromText(try label(&self.input, index));
            key.kind = 1;
            key.class = 1;
            key.dnssec = .ordinary;
            expected.* = if (index < occupancy) index else null;
        }
        const bytes = try encode(&self.input, &self.keys[0].name, .query);
        try self.service.request_packet.parse(bytes);
        try self.request.init(&self.service.request_packet);
    }

    fn deinit(self: *Fixture, allocator: std.mem.Allocator) void {
        self.service.deinit();
        allocator.destroy(self.service);
        self.* = undefined;
    }

    fn seed(
        self: *Fixture,
        allocator: std.mem.Allocator,
        bank: *Bank,
        count: u32,
        base: u32,
        kind: enum { positive, denial },
    ) !void {
        for (0..count) |index| {
            var name: wire.Name = undefined;
            try name.fromText(try label(&self.input, base + @as(u32, @intCast(index))));
            const bytes = try encode(
                &self.response,
                &name,
                if (kind == .positive) .positive else .denial,
            );
            bank.put(@intCast(index), &.{
                .key = .{ .name = name, .kind = 1, .class = 1, .dnssec = .ordinary },
                .bytes = try allocator.dupe(u8, bytes),
                .inserted_s = 100,
                .lifetime_s = 300,
            });
        }
    }
};

fn label(output: []u8, index: u32) ![]const u8 {
    return std.fmt.bufPrint(output, "host{d:0>6}.bench.example.", .{index});
}

fn encode(
    output: []u8,
    name: *const wire.Name,
    kind: enum { query, positive, denial },
) ![]const u8 {
    var encoder: wire.Encoder = undefined;
    try encoder.init(output, &.{
        .id = if (kind == .query) 42 else 0,
        .bits = switch (kind) {
            .query => 0x100,
            .positive => 0x8180,
            .denial => 0x8183,
        },
    });
    try encoder.question(name, 1, 1);
    if (kind != .query) {
        const record: wire.Record = .{
            .owner = 0,
            .kind = if (kind == .positive) 1 else 6,
            .class = 1,
            .ttl_s = 300,
            .data_start = 0,
            .data_end = 0,
            .section = if (kind == .positive) .answer else .authority,
        };
        const offset = try encoder.beginRecord(name, &record);
        if (kind == .positive) {
            try encoder.bytes(&.{ 192, 0, 2, 1 });
        } else {
            try encoder.name(name, .allowed);
            try encoder.name(name, .allowed);
            for (0..4) |_| try encoder.number(u32, 0);
            try encoder.number(u32, 300);
        }
        encoder.endRecord(offset);
    }
    return encoder.finish();
}

fn Runner(comptime capacity: u32, comptime case: Case) type {
    return struct {
        fn run(timer: *benchmark.B) !void {
            const fixture = try timer.allocator.create(Fixture);
            defer timer.allocator.destroy(fixture);
            try fixture.init(timer, capacity, case);
            defer fixture.deinit(timer.allocator);
            switch (case) {
                .index_empty_miss,
                .index_sparse_miss,
                .index_full_miss,
                .index_full_first,
                .index_full_last,
                .index_full_random,
                => try indexLoop(timer, fixture),
                .insert_evict => try churnLoop(timer, fixture, capacity),
                else => try lookupLoop(case, timer, fixture),
            }
        }
    };
}

fn indexLoop(timer: *benchmark.B, fixture: *Fixture) !void {
    const bank = &fixture.service.zones[0].cache.positive;
    var index: u32 = 0;
    var found: ?u32 = null;
    while (try timer.loop()) {
        found = bank.find(benchmark.blackBox(&fixture.keys[index % 256]));
        benchmark.keepAlive(found);
        index += 1;
    }
    if (found != fixture.expected[(index - 1) % 256]) return error.WrongIndex;
}

fn lookupLoop(comptime case: Case, timer: *benchmark.B, fixture: *Fixture) !void {
    const service = fixture.service;
    const cache = &service.zones[0].cache;
    const bytes = service.request_packet.bytes;
    var result: ?resolver.Answer = null;
    while (try timer.loop()) {
        result = if (case == .pipeline_positive_last)
            try service.answer(benchmark.blackBox(bytes), &fixture.output, .{ .udp = .ipv4 }, 101)
        else
            try cache.lookup(
                benchmark.blackBox(&fixture.request),
                101,
                &service.cache_workspace,
                &fixture.output,
            );
        benchmark.keepAlive(result);
        if (result) |answer| benchmark.keepAlive(answer.bytes);
    }
    if (case == .lookup_sparse_miss) {
        if (result != null) return error.UnexpectedHit;
    } else {
        const answer = result orelse return error.UnexpectedMiss;
        if (answer.source != .cache) return error.WrongSource;
        try service.response_packet.parse(answer.bytes);
        if (service.response_packet.header.id != 42) return error.WrongIdentifier;
        if (service.response_packet.records[0].ttl_s != 299) return error.WrongTtl;
        const rcode: u16 = if (case == .lookup_denial_last) 3 else 0;
        if (service.response_packet.header.bits & 15 != rcode) return error.WrongRcode;
    }
}

const ChurnInput = struct { name: wire.Name, bytes: [128]u8, length: u16 };

fn churnLoop(timer: *benchmark.B, fixture: *Fixture, capacity: u32) !void {
    const cache = &fixture.service.zones[0].cache;
    const workspace = &fixture.service.cache_workspace;
    const count = @min(capacity + 1, @max(128, @divTrunc(10000000, capacity)));
    const inputs = try timer.allocator.alloc(ChurnInput, count);
    defer timer.allocator.free(inputs);
    // Either the names exceed capacity or every iteration has a unique name. Each insertion evicts.
    for (inputs, 0..) |*input, index| {
        try input.name.fromText(try label(&fixture.input, capacity + @as(u32, @intCast(index))));
        input.length = @intCast((try encode(&input.bytes, &input.name, .positive)).len);
    }
    var index: u32 = 0;
    var result: resolver.cache.Result = undefined;
    while (try timer.loop()) {
        const input = &inputs[index % count];
        fixture.request.name = input.name;
        result = try cache.forward(
            benchmark.blackBox(&fixture.request),
            input.bytes[0..input.length],
            101,
            workspace,
            &fixture.output,
        );
        benchmark.keepAlive(result.answer.bytes);
        index += 1;
    }
    if (result.insertion != .stored) return error.InsertionFailed;
    const hit = (try cache.lookup(&fixture.request, 102, workspace, &fixture.output)) orelse
        return error.UnexpectedMiss;
    if (hit.source != .cache) return error.WrongSource;
}

pub fn profile(init: *const std.process.Init) !void {
    const spec = [_]benchmark.Spec{.{
        .name = "ProfilePipelinePositiveLast10000",
        .func = Runner(10000, .pipeline_positive_last).run,
    }};
    if (!try benchmark.runBenchmarks(init.gpa, &spec, .{
        .io = init.io,
        .benchtime = .{ .count = 50000 },
        .count = 1,
        .benchmem = true,
    })) return error.BenchmarkFailed;
}

pub fn layout() void {
    const Entry = resolver.cache.Entry;
    std.debug.print("Entry={d} bytes, Key={d} bytes, alignment={d} bytes\n", .{
        @sizeOf(Entry), @sizeOf(Key), @alignOf(Entry),
    });
    std.debug.print(
        "Entry offsets: key={d}, bytes={d}, inserted_s={d}, previous={d}, next={d}\n",
        .{
            @offsetOf(Entry, "key"),
            @offsetOf(Entry, "bytes"),
            @offsetOf(Entry, "inserted_s"),
            @offsetOf(Entry, "previous"),
            @offsetOf(Entry, "next"),
        },
    );
    const columns = std.MultiArrayList(Entry);
    inline for (capacities) |capacity| {
        std.debug.print("capacity={d}: two metadata column allocations={d} bytes\n", .{
            capacity, 2 * columns.capacityInBytes(capacity),
        });
    }
    std.debug.print(
        "Sizes exclude packets, allocator overhead, runtime storage, and kernel memory.\n",
        .{},
    );
}
