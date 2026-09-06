//! Synchronous admission and continuation. No packet view survives asynchronous work.
const std = @import("std");
pub const resolver = @import("../resolver.zig");
pub const wire = resolver.wire;
const config = resolver.config;
const hosts = resolver.hosts;
const cache = resolver.cache;
const udp = @import("udp.zig");
pub const Transport = union(enum) { udp: udp.Family, tcp };
pub const Error = error{ OutOfMemory, HostsLoadFailed };
pub const Admission = union(enum) { drop, answer: resolver.Answer, forward: u16 };
pub const Completion = union(enum) { response: []const u8, exhausted, local_failure };
const Zone = struct {
    cache: cache.Cache,
    hosts: ?hosts.Store = null,
    check_s: u64 = 0,
};

pub const zone_storage_bytes_max = config.zones_max * @sizeOf(Zone);

pub const Pipeline = struct {
    allocator: std.mem.Allocator,
    config: *const config.Config,
    zones: []Zone,
    request_packet: wire.Packet,
    response_packet: wire.Packet,
    cache_workspace: cache.Workspace,
    rotation: resolver.rotation.Workspace,
    intermediate: [wire.message_bytes_max]u8,
    hosts_source: [hosts.source_bytes_max + 1]u8,
    random: std.Random.DefaultPrng,

    pub fn init(
        self: *Pipeline,
        allocator: std.mem.Allocator,
        io: std.Io,
        settings: *const config.Config,
    ) Error!void {
        self.allocator = allocator;
        self.config = settings;
        self.zones = try allocator.alloc(Zone, settings.zones.len);
        errdefer allocator.free(self.zones);
        var initialized: usize = 0;
        errdefer for (self.zones[0..initialized]) |*zone| self.destroyZone(zone);
        var seed: u64 = undefined;
        io.random(std.mem.asBytes(&seed));
        self.random = .init(seed);
        for (self.zones, settings.zones) |*zone, *value| {
            zone.hosts = null;
            zone.check_s = 0;
            try zone.cache.init(allocator, value);
            initialized += 1;
            if (value.hosts) |*source| try self.loadZone(io, zone, source);
        }
    }

    fn loadZone(self: *Pipeline, io: std.Io, zone: *Zone, source: *const config.Hosts) Error!void {
        const first = try self.allocator.alloc(hosts.Entry, hosts.entries_max);
        errdefer self.allocator.free(first);
        const second = try self.allocator.alloc(hosts.Entry, hosts.entries_max);
        errdefer self.allocator.free(second);
        var store: hosts.Store = undefined;
        store.init(first, second);
        _ = store.load(io, .cwd(), source.path, &self.hosts_source) catch
            return error.HostsLoadFailed;
        zone.hosts = store;
    }

    fn destroyZone(self: *Pipeline, zone: *Zone) void {
        if (zone.hosts) |*store| {
            for (&store.tables) |*table| self.allocator.free(table.storage);
        }
        zone.cache.deinit();
    }

    pub fn deinit(self: *Pipeline) void {
        for (self.zones) |*zone| self.destroyZone(zone);
        self.allocator.free(self.zones);
        self.* = undefined;
    }

    pub fn reload(self: *Pipeline, io: std.Io, now_s: u64) void {
        for (self.zones, self.config.zones) |*zone, *settings| {
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
                return .{ .answer = .{ .bytes = output[0..12], .source = .servfail } };
            },
            .accepted => {},
        }
        var request: resolver.Request = undefined;
        try request.init(&self.request_packet);
        const selected = config.route(self.config, &request.name);
        const local = self.resolveLocal(&request, selected, now_s) catch {
            return .{ .answer = try self.failure(&request, output, 2) };
        };
        const value = local orelse return .{ .forward = selected.? };
        return .{ .answer = self.finish(&request, output, transport, selected, &value) catch
            try self.failure(&request, output, 2) };
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
        const zone = &self.zones[index];
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
            .local_failure => return self.failure(&request, output, 2),
        } catch return self.failure(&request, output, 2);
        const answer_value = self.finish(
            &request,
            output,
            transport,
            index,
            &result.answer,
        ) catch return self.failure(&request, output, 2);
        // #1: final rotation can expand compression. Publication follows its successful rewrite.
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
        return self.failure(&request, output, 2);
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
                    512;
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
        const index = selected orelse return try self.failure(request, &self.intermediate, 5);
        if (try resolver.beforeCache(request, encoder, &self.intermediate)) |hit| return hit;
        const zone = &self.zones[index];
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
        rcode: u4,
    ) wire.Error!resolver.Answer {
        const encoder = &self.cache_workspace.rewrite.encoder;
        const header: wire.Header = .{
            .id = request.packet.header.id,
            .bits = (request.packet.header.bits & 0x0110) | 0x8000 | @as(u16, rcode),
        };
        try encoder.init(output, &header);
        try encoder.question(&request.name, request.kind, request.class);
        var cookie: [44]u8 = undefined;
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
