//! Synchronous admission and continuation. No packet view survives asynchronous work.
const std = @import("std");
const Allocator = std.mem.Allocator;
const builtin = @import("builtin");

pub const resolver = @import("../resolver.zig");
pub const wire = resolver.wire;
const config = resolver.config;
const hosts = resolver.hosts;
const cache = resolver.cache;
const runtime = @import("../runtime.zig");
const udp = @import("udp.zig");

pub const Transport = union(enum) {
    udp: udp.Family,
    tcp,
};

pub const Error = error{ OutOfMemory, HostsLoadFailed };

pub const Admission = union(enum) {
    drop,
    answer: resolver.Answer,
    forward: u16,
};

pub const Completion = union(enum) {
    response: []const u8,
    exhausted,
    local_failure,
};

const Zone = struct {
    cache: cache.Cache,
    hosts: ?hosts.Store = null,
    check_s: u64 = 0,
};

pub const zone_storage_bytes_max = config.zones_max * @sizeOf(Zone);

pub const Pipeline = struct {
    allocator: Allocator,
    config: *const config.Config,
    zones: std.ArrayList(Zone),
    request_packet: wire.Packet,
    response_packet: wire.Packet,
    cache_workspace: cache.Workspace,
    rotation: resolver.rotation.Workspace,
    intermediate: [wire.message_bytes_max]u8,
    hosts_source: [hosts.source_bytes_max + 1]u8,
    random: std.Random.DefaultPrng,

    pub fn init(
        self: *Pipeline,
        allocator: Allocator,
        io: std.Io,
        settings: *const config.Config,
    ) Error!void {
        self.allocator = allocator;
        self.config = settings;
        self.zones = try .initCapacity(allocator, settings.zones.len);
        errdefer self.deinit();
        var seed: u64 = undefined;
        io.random(std.mem.asBytes(&seed));
        self.random = .init(seed);
        for (settings.zones) |*value| {
            const zone = self.zones.addOneAssumeCapacity();
            zone.hosts = null;
            zone.check_s = 0;
            zone.cache.init(allocator, value) catch |err| {
                // Cache.init releases its partial state. Cleanup visits only initialized caches.
                self.zones.shrinkRetainingCapacity(self.zones.items.len - 1);
                return err;
            };
            if (value.hosts) |*source| try self.loadZone(io, zone, source);
        }
    }

    fn loadZone(self: *Pipeline, io: std.Io, zone: *Zone, source: *const config.Hosts) Error!void {
        var store: hosts.Store = undefined;
        try store.initCapacity(self.allocator);
        errdefer store.deinit(self.allocator);
        _ = store.load(io, .cwd(), source.path, &self.hosts_source) catch
            return error.HostsLoadFailed;
        zone.hosts = store;
    }

    fn destroyZone(self: *Pipeline, zone: *Zone) void {
        if (zone.hosts) |*store| store.deinit(self.allocator);
        zone.cache.deinit();
    }

    pub fn deinit(self: *Pipeline) void {
        for (self.zones.items) |*zone| self.destroyZone(zone);
        self.zones.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn reload(self: *Pipeline, io: std.Io, now_s: u64) void {
        for (self.zones.items, self.config.zones) |*zone, *settings| {
            const source = settings.hosts orelse continue;
            if (source.reload_s == 0) continue;
            if (now_s - zone.check_s < source.reload_s) continue;
            zone.check_s = now_s;
            _ = zone.hosts.?.load(io, .cwd(), source.path, &self.hosts_source) catch continue;
        }
    }

    pub fn answer(
        self: *Pipeline,
        input: []const u8,
        output: []u8,
        transport: Transport,
        now_s: u64,
    ) wire.Error!?resolver.Answer {
        return switch (try self.begin(input, output, transport, now_s)) {
            .drop => null,
            .answer => |value| value,
            .forward => try self.localFailure(input, output),
        };
    }

    pub fn begin(
        self: *Pipeline,
        input: []const u8,
        output: []u8,
        transport: Transport,
        now_s: u64,
    ) wire.Error!Admission {
        switch (wire.query(&self.request_packet, input)) {
            .drop => return .drop,
            .reply => |header| {
                try header.encode(output);
                return .{ .answer = .{
                    .bytes = output[0..wire.header_bytes],
                    .source = .servfail,
                } };
            },
            .accepted => {},
        }
        var request: resolver.Request = undefined;
        try request.init(&self.request_packet);
        const selected = config.route(self.config, &request.name);
        const local = self.resolveLocal(&request, selected, now_s) catch {
            return .{ .answer = try self.failure(&request, output, .servfail) };
        };
        const value = local orelse return .{ .forward = selected.? };
        return .{ .answer = self.finish(&request, output, transport, selected, &value) catch
            try self.failure(&request, output, .servfail) };
    }

    pub fn complete(
        self: *Pipeline,
        input: []const u8,
        output: []u8,
        transport: Transport,
        now_s: u64,
        completion: *const Completion,
    ) wire.Error!resolver.Answer {
        try self.request_packet.parse(input);
        var request: resolver.Request = undefined;
        try request.init(&self.request_packet);
        const index = config.route(self.config, &request.name).?;
        const zone = &self.zones.items[index];
        const result = switch (completion.*) {
            .response => |bytes| zone.cache.prepareForward(
                &request,
                bytes,
                &self.cache_workspace,
                &self.intermediate,
            ),
            .exhausted => zone.cache.prepareTerminal(
                &request,
                now_s,
                &self.cache_workspace,
                &self.intermediate,
            ),
            .local_failure => return self.failure(&request, output, .servfail),
        } catch return self.failure(&request, output, .servfail);
        const answer_value = self.finish(
            &request,
            output,
            transport,
            index,
            &result.answer,
        ) catch return self.failure(&request, output, .servfail);
        // final rotation can expand compression. Publication follows its successful rewrite.
        _ = zone.cache.publish(&request, now_s, &self.cache_workspace);
        return answer_value;
    }

    pub fn localFailure(
        self: *Pipeline,
        input: []const u8,
        output: []u8,
    ) wire.Error!resolver.Answer {
        try self.request_packet.parse(input);
        var request: resolver.Request = undefined;
        try request.init(&self.request_packet);
        return self.failure(&request, output, .servfail);
    }

    fn finish(
        self: *Pipeline,
        request: *const resolver.Request,
        output: []u8,
        transport: Transport,
        selected: ?u16,
        local: *const resolver.Answer,
    ) wire.Error!resolver.Answer {
        try self.response_packet.parse(local.bytes);
        var settings: wire.rewrite.Settings = .{};
        switch (transport) {
            .udp => |family| {
                const client_bytes = if (request.packet.opt) |index|
                    request.packet.records[index].class
                else
                    wire.udp_payload_bytes_default;
                settings.limit = .{ .udp = udp.limit(client_bytes, family) };
            },
            .tcp => {},
        }
        const mode: resolver.rotation.Mode = if (selected) |index|
            (if (self.config.zones[index].rotate) .rotate else .fixed)
        else
            .fixed;
        const bytes = try self.rotation.finish(
            &self.response_packet,
            output,
            &settings,
            local.source,
            mode,
            self.random.random(),
        );
        return .{ .bytes = bytes, .source = local.source };
    }

    fn resolveLocal(
        self: *Pipeline,
        request: *const resolver.Request,
        selected: ?u16,
        now_s: u64,
    ) wire.Error!?resolver.Answer {
        const encoder = &self.cache_workspace.rewrite.encoder;
        // SPEC §3.1: no matching zone is REFUSED, including special names.
        const index = selected orelse
            return try self.failure(request, &self.intermediate, .refused);
        if (try resolver.beforeCache(request, encoder, &self.intermediate)) |hit| return hit;
        const zone = &self.zones.items[index];
        if (try zone.cache.lookup(
            request,
            now_s,
            &self.cache_workspace,
            &self.intermediate,
        )) |hit| return hit;
        const table = if (zone.hosts) |*store| store.table() else null;
        if (try resolver.afterCache(
            request,
            &self.config.zones[index],
            table,
            encoder,
            &self.intermediate,
        )) |hit| return hit;
        return null;
    }

    fn failure(
        self: *Pipeline,
        request: *const resolver.Request,
        output: []u8,
        rcode: wire.Rcode,
    ) wire.Error!resolver.Answer {
        const encoder = &self.cache_workspace.rewrite.encoder;
        const header: wire.Header = .{
            .id = request.packet.header.id,
            .bits = (request.packet.header.bits & wire.request_flags_mask) |
                wire.Flag.mask(&.{.response}) |
                @intFromEnum(rcode),
        };
        try encoder.init(output, &header);
        try encoder.question(&request.name, request.kind, request.class);
        var cookie: wire.Cookie = undefined;
        if (request.packet.opt) |index| {
            const edns: wire.rewrite.Edns = .{
                .payload_bytes = request.packet.records[index].class,
                .options = try wire.rewrite.responseOptions(request.packet, &cookie),
            };
            try wire.rewrite.writeOpt(encoder, &edns);
        }
        return .{ .bytes = try encoder.finish(), .source = .servfail };
    }
};

comptime {
    if (builtin.is_test) _ = RuntimeUnitTests;
}

const RuntimeUnitTests = struct {
    const testing = std.testing;

    // SPEC §§1, 3.5: startup failure releases initialized zones and partial caches or hosts.
    test "pipeline allocation failures release the initialized zone prefix" {
        var temporary = testing.tmpDir(.{});
        defer temporary.cleanup();
        var path_buffer: [128]u8 = undefined;
        const path = try hostsPath(&temporary, &path_buffer);
        try testing.checkAllAllocationFailures(testing.allocator, allocate, .{ path, path });
    }

    // SPEC §§1, 3.5: a failed hosts load also releases earlier zones and the current cache.
    test "pipeline hosts load failure releases complete and incomplete zones" {
        var temporary = testing.tmpDir(.{});
        defer temporary.cleanup();
        var path_buffer: [128]u8 = undefined;
        const path = try hostsPath(&temporary, &path_buffer);
        var missing_buffer: [160]u8 = undefined;
        const missing = try std.fmt.bufPrint(&missing_buffer, "{s}.missing", .{path});
        try testing.expectError(error.HostsLoadFailed, allocate(testing.allocator, path, missing));
    }

    fn hostsPath(temporary: *testing.TmpDir, buffer: []u8) ![]const u8 {
        try temporary.dir.writeFile(testing.io, .{
            .sub_path = "hosts",
            .data = "192.0.2.1 entry.example\n",
        });
        return std.fmt.bufPrint(buffer, ".zig-cache/tmp/{s}/hosts", .{temporary.sub_path});
    }

    fn allocate(allocator: Allocator, first_path: []const u8, second_path: []const u8) !void {
        const service = try allocator.create(Pipeline);
        defer allocator.destroy(service);
        var zones: [2]config.Zone = undefined;
        for (&zones, 0..) |*zone, index| {
            zone.* = .{
                .suffix = if (index == 0) "one." else "two.",
                .hosts = .{ .path = if (index == 0) first_path else second_path },
                .upstreams = &.{.{ .address = "127.0.0.1:9" }},
                .cache = .{ .capacity = 1, .packet_bytes_max = 64 * 1024 },
            };
        }
        const settings: config.Config = .{ .zones = &zones };
        try service.init(allocator, testing.io, &settings);
        defer service.deinit();
        try testing.expectEqual(@as(usize, 2), service.zones.items.len);
        try testing.expectEqual(@as(usize, 2), service.zones.capacity);
        for (service.zones.items) |*zone| {
            try testing.expectEqual(@as(usize, 1), zone.hosts.?.table().entries().len);
        }
    }
};

comptime {
    if (builtin.is_test) _ = RuntimeUnitTestsLegacy;
}

const RuntimeUnitTestsLegacy = struct {
    const testing = std.testing;
    const linux = std.os.linux;

    // SPEC §3.5: enabled hosts loads initially even when its periodic check is disabled.
    test "initial hosts failure and startup allocation rollback" {
        const pipeline = try testing.allocator.create(runtime.pipeline.Pipeline);
        defer testing.allocator.destroy(pipeline);
        var zones = [_]runtime.pipeline.resolver.config.Zone{.{
            .suffix = ".",
            .upstreams = &.{.{ .address = "127.0.0.1:1" }},
            .cache = .{ .capacity = 1 },
            .hosts = .{ .path = "/nonexistent-z53-test/hosts", .reload_s = 0 },
        }};
        const settings: runtime.pipeline.resolver.config.Config = .{ .zones = &zones };
        try testing.expectError(
            error.HostsLoadFailed,
            pipeline.init(testing.allocator, testing.io, &settings),
        );
        for (0..5) |index| {
            var failing = testing.FailingAllocator.init(
                testing.allocator,
                .{ .fail_index = index },
            );
            try testing.expectError(
                error.OutOfMemory,
                pipeline.init(failing.allocator(), testing.io, &settings),
            );
        }
    }

    // SPEC §3.2: unresolved forwarding is a local failure, never a stale/cache insertion.
    test "local pipeline and explicit unresolved forwarding" {
        const pipeline = try testing.allocator.create(runtime.pipeline.Pipeline);
        defer testing.allocator.destroy(pipeline);
        var zones = [_]runtime.pipeline.resolver.config.Zone{.{
            .suffix = ".",
            .upstreams = &.{.{ .address = "127.0.0.1:1" }},
            .cache = .{ .capacity = 1 },
        }};
        const settings: runtime.pipeline.resolver.config.Config = .{ .zones = &zones };
        var allocator = testing.FailingAllocator.init(testing.allocator, .{});
        try pipeline.init(allocator.allocator(), testing.io, &settings);
        defer pipeline.deinit();
        const allocations = allocator.alloc_index;
        allocator.fail_index = allocations;
        var input: [512]u8 = undefined;
        var output: [65535]u8 = undefined;
        var encoder: wire.Encoder = undefined;
        var name: wire.Name = undefined;
        try name.fromText("localhost.");
        try encoder.init(&input, &.{ .id = 42, .bits = 0x100 });
        try encoder.question(&name, .a, 1);
        const local = (try pipeline.answer(try encoder.finish(), &output, .{ .udp = .ipv4 }, 0)).?;
        try testing.expectEqual(.rfc6761, local.source);
        try testing.expectEqual(0x8500, (try wire.Header.decode(local.bytes)).bits);
        try name.fromText("missing.example.");
        try encoder.init(&input, &.{ .id = 43 });
        try encoder.question(&name, .a, 1);
        const missing = (try pipeline.answer(try encoder.finish(), &output, .tcp, 0)).?;
        try testing.expectEqual(.servfail, missing.source);
        try testing.expectEqual(2, (try wire.Header.decode(missing.bytes)).bits & 15);
        try testing.expectEqual(
            null,
            pipeline.zones.items[0].cache.positive.entries.items(.bytes)[0],
        );
        try testing.expectEqual(
            null,
            pipeline.zones.items[0].cache.denial.entries.items(.bytes)[0],
        );
        try testing.expectEqual(allocations, allocator.alloc_index);
        try testing.expect(!allocator.has_induced_failure);
    }
};
