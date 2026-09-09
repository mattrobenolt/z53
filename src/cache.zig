//! One cache per routed zone. All methods are synchronous on one event thread.
//! Output, request bytes and workspace must be disjoint. Delivery is full-size TCP;
//! the runtime applies rotation and client UDP limits afterward, never before insertion.
const std = @import("std");
const assert = std.debug.assert;
const builtin = @import("builtin");

pub const packets = @import("cache/packets.zig");
const policy = @import("cache/policy.zig");
const store = @import("cache/store.zig");
pub const Entry = store.Entry;
const config = @import("config.zig");
const resolver = @import("resolver.zig");
const test_fixture = @import("testing/cache.zig");
const wire = @import("wire.zig");

pub const Insertion = enum { stored, skipped, exhausted };

pub const Result = struct {
    answer: resolver.Answer,
    insertion: Insertion,
};

pub const Workspace = struct {
    packet: wire.Packet,
    rewrite: wire.rewrite.Workspace,
    storage: [wire.message_bytes_max]u8,
    publication: ?struct { selected: policy.Policy, length: u32 } = null,
};

pub const Cache = struct {
    allocator: std.mem.Allocator,
    settings: ?config.Cache,
    grace_s: u32,
    positive: store.Bank = .{},
    denial: store.Bank = .{},
    packet_storage: packets.Storage = .{},

    /// The validated zone supplies bounds. Failure invalidates self and releases owned storage.
    pub fn init(
        self: *Cache,
        allocator: std.mem.Allocator,
        zone: *const config.Zone,
    ) error{OutOfMemory}!void {
        self.* = .{ .allocator = allocator, .settings = zone.cache, .grace_s = zone.serve_stale_s };
        const settings = self.settings orelse return;
        assert(settings.capacity > 0);
        assert(settings.capacity <= config.cache_capacity_max);
        assert(settings.packet_bytes_max >= config.cache_packet_bytes_min);
        assert(settings.packet_bytes_max <= config.cache_packet_bytes_max);
        assert(settings.min_ttl_s <= settings.max_ttl_s);
        assert(settings.denialMaximum() >= 5);
        try self.positive.init(allocator, settings.capacity);
        errdefer self.positive.deinit(allocator);
        try self.denial.init(allocator, settings.capacity);
        errdefer self.denial.deinit(allocator);
        try self.packet_storage.init(allocator, settings.packet_bytes_max);
    }

    pub fn deinit(self: *Cache) void {
        self.positive.deinit(self.allocator);
        self.denial.deinit(self.allocator);
        self.packet_storage.deinit(self.allocator);
        self.* = undefined;
    }

    /// An expired entry is a miss, not a stale answer: upstreams must be attempted first.
    pub fn lookup(
        self: *Cache,
        request: *const resolver.Request,
        now_s: u64,
        workspace: *Workspace,
        output: []u8,
    ) wire.Error!?resolver.Answer {
        var key: store.Key = undefined;
        key.init(request);
        for ([_]*store.Bank{ &self.positive, &self.denial }) |bank| {
            const index = bank.find(&key) orelse continue;
            const entry = bank.entries.get(index);
            if (entry.age(now_s) >= entry.lifetime_s) return null;
            const answer = try serve(&entry, request, now_s, workspace, output, .cache);
            bank.touch(index);
            return answer;
        }
        return null;
    }

    /// Only accepted upstream responses use this seam. Synthetic/local encoding errors
    /// have no insertion API. A rewrite error leaves both banks unchanged.
    pub fn forward(
        self: *Cache,
        request: *const resolver.Request,
        response: []const u8,
        now_s: u64,
        workspace: *Workspace,
        output: []u8,
    ) wire.Error!Result {
        var result = try self.prepareForward(request, response, workspace, output);
        result.insertion = self.publish(request, now_s, workspace);
        return result;
    }

    /// The runtime must finish rotation and client encoding before publication.
    pub fn prepareForward(
        self: *Cache,
        request: *const resolver.Request,
        response: []const u8,
        workspace: *Workspace,
        output: []u8,
    ) wire.Error!Result {
        workspace.publication = null;
        try workspace.packet.parse(response);
        if (request.packet.opt == null) {
            if (workspace.packet.opt) |index| {
                if (workspace.packet.records[index].ttl_s >> wire.edns_rcode_shift != 0) {
                    return localFailure(request, &workspace.rewrite.encoder, output);
                }
            }
        }
        workspace.packet.header.bits = resolver.Source.forward.responseBits(
            workspace.packet.header.bits,
        );
        const selected = if (self.settings) |*settings|
            policy.classify(&workspace.packet, settings, request.kind)
        else
            null;
        if (selected) |*value| policy.apply(&workspace.packet, value, &self.settings.?);
        // Prove the current client can receive a compliant response before publishing it.
        const answer = try deliver(request, workspace, output, .forward);
        const value = selected orelse return .{ .answer = answer, .insertion = .skipped };
        const settings: wire.rewrite.Settings = .{
            .id = 0,
            .question = .{ .name = &request.name, .kind = request.kind, .class = request.class },
            .opt = .omit,
        };
        const bytes = try workspace.rewrite.rewrite(
            &workspace.packet,
            &workspace.storage,
            &settings,
        );
        workspace.publication = .{ .selected = value, .length = @intCast(bytes.len) };
        return .{ .answer = answer, .insertion = .skipped };
    }

    /// No packet or rewrite operation can fail after this commit point.
    pub fn publish(
        self: *Cache,
        request: *const resolver.Request,
        now_s: u64,
        workspace: *Workspace,
    ) Insertion {
        const publication = workspace.publication orelse return .skipped;
        workspace.publication = null;
        var key: store.Key = undefined;
        key.init(request);
        return self.insert(
            &key,
            workspace.storage[0..publication.length],
            now_s,
            &publication.selected,
        ) catch .exhausted;
    }

    /// Call only after every upstream transport failed. An upstream SERVFAIL is instead
    /// an ordinary forward response and must not trigger this stale path.
    pub fn terminalFailure(
        self: *Cache,
        request: *const resolver.Request,
        now_s: u64,
        workspace: *Workspace,
        output: []u8,
    ) wire.Error!Result {
        var result = try self.prepareTerminal(request, now_s, workspace, output);
        result.insertion = self.publish(request, now_s, workspace);
        return result;
    }

    pub fn prepareTerminal(
        self: *Cache,
        request: *const resolver.Request,
        now_s: u64,
        workspace: *Workspace,
        output: []u8,
    ) wire.Error!Result {
        workspace.publication = null;
        var key: store.Key = undefined;
        key.init(request);
        for ([_]*store.Bank{ &self.positive, &self.denial }) |bank| {
            const index = bank.find(&key) orelse continue;
            const entry = bank.entries.get(index);
            if (!entry.stale(now_s, self.grace_s)) continue;
            const answer = try serve(
                &entry,
                request,
                now_s,
                workspace,
                output,
                .stale,
            );
            bank.touch(index);
            return .{ .answer = answer, .insertion = .skipped };
        }
        var failure: [wire.udp_payload_bytes_default]u8 = undefined;
        const header: wire.Header = .{
            .id = request.packet.header.id,
            .bits = (request.packet.header.bits & wire.request_flags_mask) |
                wire.Flag.mask(&.{ .response, .recursion_available }) |
                @intFromEnum(wire.Rcode.servfail),
        };
        const encoder = &workspace.rewrite.encoder;
        try encoder.init(&failure, &header);
        try encoder.question(&request.name, request.kind, request.class);
        var result = try self.prepareForward(request, try encoder.finish(), workspace, output);
        result.answer.source = .servfail;
        return result;
    }

    fn insert(
        self: *Cache,
        key: *const store.Key,
        bytes: []const u8,
        now_s: u64,
        selected: *const policy.Policy,
    ) error{OutOfMemory}!Insertion {
        assert(bytes.len <= wire.message_bytes_max);
        const bank = if (selected.bank == .positive) &self.positive else &self.denial;
        const other = if (selected.bank == .positive) &self.denial else &self.positive;
        const index = bank.slot(key);
        const old = other.find(key);
        const packet_class = packets.class(bytes.len);
        // Reuse only the destination victim or this key in the other bank.
        // Rewrites already succeeded. Nothing can fail after a block transfer.
        const owned = self.reuse(bank, index, bytes.len) orelse
            (if (old) |value| self.reuse(other, value, bytes.len) else null) orelse
            try self.packet_storage.create(bytes.len);
        @memcpy(owned, bytes);
        if (bank.entries.items(.bytes)[index] != null) {
            bank.remove(&self.packet_storage, index);
        }
        if (old) |value| {
            if (other.entries.items(.bytes)[value] != null) {
                other.remove(&self.packet_storage, value);
            }
        }
        bank.put(index, &.{
            .key = key.*,
            .bytes = owned,
            .packet_class = packet_class,
            .inserted_s = now_s,
            .lifetime_s = selected.lifetime_s,
            .category = if (selected.category == .answer) .answer else .failure,
        });
        return .stored;
    }

    fn reuse(self: *Cache, bank: *store.Bank, index: u32, length: usize) ?[]u8 {
        _ = bank.entries.items(.bytes)[index] orelse return null;
        if (bank.entries.items(.packet_class)[index] != packets.class(length)) return null;
        const owned = bank.take(index);
        self.packet_storage.live_bytes -= @intCast(owned.len);
        self.packet_storage.live_bytes += @intCast(length);
        return owned.ptr[0..length];
    }
};

/// RFC 6891 §6.1.3: a client without OPT cannot receive an extended RCODE.
/// This local failure bypasses both cache publication and terminal transport handling.
fn localFailure(
    request: *const resolver.Request,
    encoder: *wire.Encoder,
    output: []u8,
) wire.Error!Result {
    assert(request.packet.opt == null);
    const header: wire.Header = .{
        .id = request.packet.header.id,
        .bits = (request.packet.header.bits & wire.request_flags_mask) |
            wire.Flag.mask(&.{ .response, .recursion_available }) |
            @intFromEnum(wire.Rcode.servfail),
    };
    try encoder.init(output, &header);
    try encoder.question(&request.name, request.kind, request.class);
    return .{
        .answer = .{ .bytes = try encoder.finish(), .source = .servfail },
        .insertion = .skipped,
    };
}

fn serve(
    entry: *const Entry,
    request: *const resolver.Request,
    now_s: u64,
    workspace: *Workspace,
    output: []u8,
    source: resolver.Source,
) wire.Error!resolver.Answer {
    try workspace.packet.parse(entry.bytes.?);
    for (workspace.packet.records[0..workspace.packet.record_count]) |*record| {
        if (record.kind == .opt) continue;
        record.ttl_s = if (source == .stale)
            30
        else
            record.ttl_s -| @as(u32, @intCast(entry.age(now_s)));
    }
    return deliver(request, workspace, output, source);
}

fn deliver(
    request: *const resolver.Request,
    workspace: *Workspace,
    output: []u8,
    source: resolver.Source,
) wire.Error!resolver.Answer {
    var cookie: wire.Cookie = undefined;
    var edns: wire.rewrite.Edns = .{ .payload_bytes = wire.udp_payload_bytes_default };
    var settings: wire.rewrite.Settings = .{
        .id = request.packet.header.id,
        .question = .{ .name = &request.name, .kind = request.kind, .class = request.class },
        .opt = .omit,
    };
    if (request.packet.opt) |index| {
        edns.payload_bytes = request.packet.records[index].class;
        edns.flags = @as(u16, @truncate(request.packet.records[index].ttl_s)) & wire.edns_dnssec_ok;
        edns.options = try wire.rewrite.responseOptions(request.packet, &cookie);
        if (workspace.packet.opt) |upstream| {
            const ttl = workspace.packet.records[upstream].ttl_s;
            edns.extended_rcode = @truncate(ttl >> wire.edns_rcode_shift);
        }
        settings.opt = .{ .replace = &edns };
    }
    return .{
        .bytes = try workspace.rewrite.rewrite(&workspace.packet, output, &settings),
        .source = source,
    };
}

comptime {
    if (builtin.is_test) _ = ResolverTestsCacheErrors;
}

const ResolverTestsCacheErrors = struct {
    const testing = test_fixture.testing;

    // SPEC §§1.10, 3.7: all general-purpose allocation ends at initialization.
    test "cache allocation budget covers insertion refresh lookup and stale delivery" {
        var allocator = testing.FailingAllocator.init(testing.allocator, .{});
        var fixture: test_fixture.Fixture = undefined;
        try fixture.init(allocator.allocator(), &test_fixture.zone);
        defer fixture.cache.deinit();
        try testing.expectEqual(@as(usize, 5), allocator.allocations);
        allocator.fail_index = allocator.alloc_index;
        try testing.expect(@sizeOf(test_fixture.cache.Entry) <= 320);
        try fixture.response(0x8500);
        try fixture.record(1, .answer, 5, 0);
        _ = try fixture.forward(0);
        try testing.expectEqual(@as(usize, 5), allocator.allocations);
        allocator.fail_index = allocator.alloc_index;
        const held = allocator.allocated_bytes - allocator.freed_bytes;
        for (0..32) |_| {
            try testing.expect((try fixture.lookup(1)) != null);
            try testing.expectEqual(null, try fixture.lookup(5));
            try testing.expectEqual(.stale, (try fixture.failure(5)).answer.source);
        }
        try testing.expect(!allocator.has_induced_failure);
        const result = try fixture.forward(5);
        try testing.expectEqual(.stored, result.insertion);
        try testing.expect(!allocator.has_induced_failure);
        try testing.expectEqual(held, allocator.allocated_bytes - allocator.freed_bytes);
        try testing.expectEqual(.stale, (try fixture.failure(10)).answer.source);
        try testing.expectEqual(@as(usize, 5), allocator.allocations);
    }

    // SPEC §§1.11, 3.7: each startup allocation failure releases all preceding owned storage.
    test "cache startup allocation failures roll back" {
        for (0..5) |fail_index| {
            var allocator = testing.FailingAllocator.init(testing.allocator, .{
                .fail_index = fail_index,
            });
            var cache: test_fixture.cache.Cache = undefined;
            try testing.expectError(
                error.OutOfMemory,
                cache.init(allocator.allocator(), &test_fixture.zone),
            );
            try testing.expect(allocator.has_induced_failure);
            try testing.expectEqual(allocator.allocated_bytes, allocator.freed_bytes);
        }
    }

    // SPEC §3.9: local encoding failure never publishes an entry or becomes transport failure.
    test "cache malformed input and short encoding failure leave stale candidate unchanged" {
        var fixture: test_fixture.Fixture = undefined;
        try fixture.init(testing.allocator, &test_fixture.zone);
        defer fixture.cache.deinit();
        try fixture.response(0x8500);
        try fixture.record(1, .answer, 5, 0);
        _ = try fixture.forward(0);
        const bytes = try fixture.encoder.finish();
        try testing.expectError(error.NoSpace, fixture.cache.forward(
            &fixture.client.request,
            bytes,
            5,
            &fixture.workspace,
            fixture.client.output[0..12],
        ));
        try testing.expectError(error.Truncated, fixture.cache.forward(
            &fixture.client.request,
            bytes[0..10],
            5,
            &fixture.workspace,
            &fixture.client.output,
        ));
        try testing.expectError(error.NoSpace, fixture.cache.terminalFailure(
            &fixture.client.request,
            5,
            &fixture.workspace,
            fixture.client.output[0..12],
        ));
        try testing.expectEqual(null, try fixture.lookup(5));
        try testing.expectEqual(.stale, (try fixture.failure(5)).answer.source);
    }

    // SPEC §3.9; RFC 2782: 300 compressed SRV targets expand beyond 65535, never
    // cache local SERVFAIL.
    test "cache rejects RewriteTooLarge before insertion" {
        var fixture: test_fixture.Fixture = undefined;
        try fixture.init(testing.allocator, &test_fixture.zone);
        defer fixture.cache.deinit();
        var name: wire.Name = .{};
        name.length = 255;
        var cursor: usize = 0;
        for ([_]u8{ 63, 63, 63, 61 }) |length| {
            name.bytes[cursor] = length;
            cursor += 1;
            @memset(name.bytes[cursor..][0..length], 'a');
            cursor += length;
        }
        name.bytes[cursor] = 0;
        fixture.client.request.name = name;
        try fixture.response(0x8500);
        // Encode the legacy compressed receive layout directly; the normal encoder forbids it.
        for (0..300) |_| {
            try fixture.encoder.bytes(&.{ 0xc0, 0x0c });
            try fixture.encoder.number(u16, 33);
            try fixture.encoder.number(u16, 1);
            try fixture.encoder.number(u32, 60);
            try fixture.encoder.number(u16, 8);
            try fixture.encoder.bytes(&.{ 0, 0, 0, 0, 0, 53, 0xc0, 0x0c });
            fixture.encoder.header.counts[1] += 1;
        }
        try testing.expectError(error.RewriteTooLarge, fixture.forward(0));
        try testing.expectEqual(null, try fixture.lookup(0));
        for (fixture.cache.positive.entries.items(.bytes)) |bytes| {
            try testing.expectEqual(null, bytes);
        }
        for (fixture.cache.denial.entries.items(.bytes)) |bytes| {
            try testing.expectEqual(null, bytes);
        }
    }

    // SPEC §3.7: capacity-one churn reuses packet blocks within the startup allocation.
    test "cache bounded capacity one churn and zone isolation" {
        var allocator = testing.FailingAllocator.init(testing.allocator, .{});
        var fixture: test_fixture.Fixture = undefined;
        var zone = test_fixture.zone;
        zone.cache.?.capacity = 1;
        try fixture.init(allocator.allocator(), &zone);
        defer fixture.cache.deinit();
        allocator.fail_index = allocator.alloc_index;
        var isolated: test_fixture.cache.Cache = undefined;
        try isolated.init(testing.allocator, &zone);
        defer isolated.deinit();
        for (0..64) |index| {
            try fixture.client.init(if (index % 2 == 0) "one." else "two.", 1, 1);
            try fixture.response(0x8500);
            try fixture.record(1, .answer, 60, 0);
            _ = try fixture.forward(0);
            try testing.expectEqual(@as(usize, 5), allocator.allocations - allocator.deallocations);
            try testing.expect(!allocator.has_induced_failure);
            const bound = 2 * 384 + zone.cache.?.packet_bytes_max;
            try testing.expect(allocator.allocated_bytes - allocator.freed_bytes <= bound);
            try testing.expectEqual(null, try isolated.lookup(
                &fixture.client.request,
                0,
                &fixture.workspace,
                &fixture.client.output,
            ));
        }
    }
};

comptime {
    if (builtin.is_test) _ = ResolverTestsCache;
}

const ResolverTestsCache = struct {
    const testing = test_fixture.testing;

    // SPEC §3.7; RFC 1035 §4.1.3: clamp every non-OPT TTL, age from insertion, expire at minimum.
    test "cache positive TTL clamps and deterministic aging preserve upstream flags" {
        var fixture: test_fixture.Fixture = undefined;
        try fixture.init(testing.allocator, &test_fixture.zone);
        defer fixture.cache.deinit();
        try fixture.response(0x8520);
        try fixture.record(1, .answer, 0, 0);
        try fixture.record(1, .authority, 4000, 0);
        try fixture.record(1, .additional, 20, 0);
        const result = try fixture.forward(100);
        try testing.expectEqual(.stored, result.insertion);
        try fixture.ttl(&result.answer, 5);
        try testing.expectEqual(@as(u32, 3600), fixture.client.response.records[1].ttl_s);
        try testing.expectEqual(@as(u16, 0x85a0), fixture.client.response.header.bits);
        const hit = (try fixture.lookup(104)).?;
        try testing.expectEqual(.cache, hit.source);
        try fixture.ttl(&hit, 1);
        try testing.expectEqual(@as(u32, 3596), fixture.client.response.records[1].ttl_s);
        try testing.expectEqual(@as(u32, 16), fixture.client.response.records[2].ttl_s);
        try testing.expectEqual(null, try fixture.lookup(105));
        const stale = try fixture.failure(105);
        try fixture.ttl(&stale.answer, 30);
        for (fixture.client.response.records[0..3]) |record| {
            try testing.expectEqual(@as(u32, 30), record.ttl_s);
        }
    }

    // SPEC §3.7; RFC 2308 §3, §5: NXDOMAIN/NODATA use min(SOA TTL, MINIMUM), fixed floor five.
    test "cache denial clamps ignore positive minimum and share positive maximum cap" {
        var fixture: test_fixture.Fixture = undefined;
        var zone = test_fixture.zone;
        zone.cache = .{ .capacity = 2, .min_ttl_s = 20, .max_ttl_s = 30, .neg_max_ttl_s = 25 };
        try fixture.init(testing.allocator, &zone);
        defer fixture.cache.deinit();
        for ([_]u16{ 0x8500, 0x8503 }) |bits| {
            const cases = [_][3]u32{
                .{ 0, 100, 5 }, .{ 100, 2, 5 }, .{ 10, 100, 10 }, .{ 100, 100, 25 },
            };
            for (cases) |values| {
                try fixture.response(bits);
                try fixture.record(6, .authority, values[0], values[1]);
                const result = try fixture.forward(0);
                try testing.expectEqual(.stored, result.insertion);
                try fixture.ttl(&result.answer, values[2]);
                const hit = (try fixture.lookup(values[2] - 1)).?;
                try fixture.ttl(&hit, 1);
                try testing.expectEqual(null, try fixture.lookup(values[2]));
            }
        }
        fixture.cache.settings.?.neg_max_ttl_s = 1800;
        try fixture.response(0x8503);
        try fixture.record(5, .answer, 100, 0);
        try fixture.record(6, .authority, 100, 100);
        const capped = try fixture.forward(0);
        try fixture.ttl(&capped.answer, 30);
        try testing.expectEqual(@as(u32, 30), fixture.workspace.packet.records[1].ttl_s);
        try fixture.response(0x8500);
        try fixture.record(5, .answer, 100, 0);
        try fixture.record(6, .authority, 100, 100);
        _ = try fixture.forward(0);
        const entry = fixture.cache.denial.entries.get(fixture.cache.denial.first.?);
        try testing.expectEqual(@as(u32, 30), entry.lifetime_s);
    }

    // SPEC §3.7; RFC 6891 §6.1.3: class/type/framed case-insensitive name/DO key
    // excludes client ID.
    test "cache key dimensions and per-client question EDNS COOKIE rewriting" {
        var fixture: test_fixture.Fixture = undefined;
        try fixture.init(testing.allocator, &test_fixture.zone);
        defer fixture.cache.deinit();
        const first_cookie = .{ 0, 10, 0, 8 } ++ .{1} ** 8;
        const next_cookie = .{ 0, 10, 0, 8 } ++ .{2} ** 8;
        try fixture.client.edns(&first_cookie);
        try fixture.response(0x8500);
        try fixture.record(1, .answer, 60, 0);
        const edns: wire.rewrite.Edns = .{
            .payload_bytes = 1232,
            .flags = 0x8000,
            .options = &first_cookie,
        };
        try wire.rewrite.writeOpt(&fixture.encoder, &edns);
        _ = try fixture.forward(0);
        const bank = &fixture.cache.positive;
        const stored = bank.entries.items(.bytes)[bank.first.?].?;
        try fixture.client.response.parse(stored);
        try testing.expectEqual(null, fixture.client.response.opt);
        try testing.expectEqual(@as(u16, 0), fixture.client.response.header.id);
        try fixture.client.init("EXAMPLE.", 1, 1);
        try testing.expectEqual(null, try fixture.lookup(1));
        try fixture.client.edns(&(next_cookie ++ .{ 0xfd, 0xe8, 0, 0 }));
        fixture.client.query.header.id = 42;
        fixture.client.query.records[fixture.client.query.opt.?].class = 4096;
        const hit = (try fixture.lookup(1)).?;
        try fixture.ttl(&hit, 59);
        const response = &fixture.client.response;
        try testing.expectEqual(@as(u16, 42), response.header.id);
        var cursor: usize = 12;
        const question = try response.readQuestion(&cursor);
        var name: wire.Name = undefined;
        try response.name(&name, question.name);
        try testing.expectEqualSlices(u8, fixture.client.request.name.wire(), name.wire());
        const opt = response.records[response.opt.?];
        try testing.expectEqual(@as(u16, 4096), opt.class);
        try testing.expectEqual(@as(u32, 0x8000), opt.ttl_s);
        try testing.expectEqualSlices(u8, &next_cookie, hit.bytes[opt.data_start..opt.data_end]);
        fixture.client.request.class = 3;
        try testing.expectEqual(null, try fixture.lookup(1));
        fixture.client.request.class = 1;
        fixture.client.request.kind = .aaaa;
        try testing.expectEqual(null, try fixture.lookup(1));
        fixture.client.request.kind = .a;
        try fixture.client.request.name.fromText("other.");
        try testing.expectEqual(null, try fixture.lookup(1));
    }

    // SPEC §3.7; RFC 8767 §5: only exhausted transports unlock stale, with an
    // exclusive grace end.
    test "stale precedes terminal SERVFAIL without replacing or extending its candidate" {
        var fixture: test_fixture.Fixture = undefined;
        try fixture.init(testing.allocator, &test_fixture.zone);
        defer fixture.cache.deinit();
        try fixture.response(0x8500);
        try fixture.record(1, .answer, 5, 0);
        _ = try fixture.forward(std.math.maxInt(u64) - 20);
        for ([_]u64{ 5, 14 }) |elapsed| {
            const now_s = std.math.maxInt(u64) - 20 + elapsed;
            try testing.expectEqual(null, try fixture.lookup(now_s));
            const result = try fixture.failure(now_s);
            try testing.expectEqual(.stale, result.answer.source);
            try testing.expectEqual(.skipped, result.insertion);
            try fixture.ttl(&result.answer, 30);
        }
        const result = try fixture.failure(std.math.maxInt(u64) - 5);
        try testing.expectEqual(.servfail, result.answer.source);
        try testing.expectEqual(.stored, result.insertion);
        const hit = (try fixture.lookup(std.math.maxInt(u64) - 1)).?;
        try fixture.client.response.parse(hit.bytes);
        try testing.expectEqual(@as(u16, 2), fixture.client.response.header.bits & 15);
        try testing.expectEqual(null, try fixture.lookup(std.math.maxInt(u64)));
        const again = try fixture.failure(std.math.maxInt(u64));
        try testing.expectEqual(.servfail, again.answer.source);
    }

    // SPEC §3.6–3.7: upstream SERVFAIL is an answer, not transport exhaustion or
    // stale eligibility.
    test "upstream SERVFAIL caches five seconds and stale disabled means terminal failure" {
        var fixture: test_fixture.Fixture = undefined;
        var zone = test_fixture.zone;
        zone.serve_stale_s = 0;
        try fixture.init(testing.allocator, &zone);
        defer fixture.cache.deinit();
        try fixture.response(0x8500);
        try fixture.record(1, .answer, 5, 0);
        _ = try fixture.forward(0);
        const terminal = try fixture.failure(5);
        try testing.expectEqual(.servfail, terminal.answer.source);
        try testing.expectEqual(null, try fixture.lookup(10));
        try fixture.response(0x8502);
        _ = try fixture.forward(10);
        try testing.expect((try fixture.lookup(14)) != null);
        try testing.expectEqual(null, try fixture.lookup(15));
        fixture.cache.grace_s = 100;
        const failure = try fixture.failure(15);
        try testing.expectEqual(.servfail, failure.answer.source);
    }

    // SPEC §3.7: independent LRUs refresh hit recency; replacements change banks.
    test "cache LRU eviction is independent for positive and denial entries" {
        var fixture: test_fixture.Fixture = undefined;
        try fixture.init(testing.allocator, &test_fixture.zone);
        defer fixture.cache.deinit();
        for ([_]u16{ 0x8500, 0x8503 }) |bits| {
            for ([_][]const u8{ "one.", "two.", "three." }, 0..) |name, index| {
                if (index == 2) {
                    try fixture.client.init("one.", 1, 1);
                    try testing.expect((try fixture.lookup(0)) != null);
                }
                try fixture.client.init(name, 1, 1);
                try fixture.response(bits);
                if (bits == 0x8500) {
                    try fixture.record(1, .answer, 60, 0);
                } else try fixture.record(6, .authority, 60, 60);
                _ = try fixture.forward(0);
            }
            try fixture.client.init("two.", 1, 1);
            try testing.expectEqual(null, try fixture.lookup(0));
            try fixture.client.init("one.", 1, 1);
            try testing.expect((try fixture.lookup(0)) != null);
        }
        try testing.expectEqual(@as(usize, 2), fixture.cache.positive.entries.len);
        try testing.expectEqual(@as(usize, 2), fixture.cache.denial.entries.len);
        // The denial replacement removed the matching positive entries, rather than shadowing them.
        for (fixture.cache.positive.entries.items(.bytes)) |bytes| {
            try testing.expectEqual(null, bytes);
        }
    }

    // SPEC §3.7; RFC 2308 §5: incomplete and uncacheable errors cannot evict an existing answer.
    test "cache skips truncation unsupported rcodes missing SOA and disabled zones" {
        var fixture: test_fixture.Fixture = undefined;
        try fixture.init(testing.allocator, &test_fixture.zone);
        defer fixture.cache.deinit();
        for ([_]u16{ 0x8300, 0x8105, 0x8103, 0x8100, 0x0100 }) |bits| {
            try fixture.response(bits);
            const result = try fixture.forward(0);
            try testing.expectEqual(.skipped, result.insertion);
            try testing.expectEqual(null, try fixture.lookup(0));
        }
        try fixture.response(0x8100);
        try fixture.record(1, .answer, 60, 0);
        const edns: wire.rewrite.Edns = .{ .payload_bytes = 1232, .extended_rcode = 1 };
        try wire.rewrite.writeOpt(&fixture.encoder, &edns);
        try testing.expectEqual(.skipped, (try fixture.forward(0)).insertion);
        fixture.cache.deinit();
        var zone = test_fixture.zone;
        zone.cache = null;
        try fixture.cache.init(testing.allocator, &zone);
        try fixture.response(0x8500);
        try fixture.record(1, .answer, 0, 0);
        const result = try fixture.forward(0);
        try testing.expectEqual(.skipped, result.insertion);
        try fixture.ttl(&result.answer, 0);
        try testing.expectEqual(null, try fixture.lookup(0));
    }
};

comptime {
    if (builtin.is_test) _ = ResolverTestsCacheRcode;
}

const ResolverTestsCacheRcode = struct {
    const testing = test_fixture.testing;

    // SPEC §3.9; RFC 6891 §6.1.3: extended errors cannot be represented without client EDNS.
    test "cache extended errors without EDNS become uncached local SERVFAIL" {
        for ([_]?test_fixture.resolver.config.Cache{ test_fixture.zone.cache, null }) |settings| {
            var zone = test_fixture.zone;
            zone.cache = settings;
            var fixture: test_fixture.Fixture = undefined;
            try fixture.init(testing.allocator, &zone);
            defer fixture.cache.deinit();
            try fixture.client.init("ExAmPlE.", 28, 3);
            for ([_]u8{ 1, 255 }) |extended| {
                for ([_]u16{ 0, 2, 3 }) |low| {
                    try fixture.response(0x8520 | low);
                    const edns: wire.rewrite.Edns = .{
                        .payload_bytes = 1232,
                        .extended_rcode = extended,
                    };
                    try wire.rewrite.writeOpt(&fixture.encoder, &edns);
                    const result = try fixture.forward(0);
                    try testing.expectEqual(.servfail, result.answer.source);
                    try testing.expectEqual(.skipped, result.insertion);
                    try fixture.client.response.parse(result.answer.bytes);
                    try testing.expectEqual(@as(u16, 0x8192), fixture.client.response.header.bits);
                    try testing.expectEqual(@as(u16, 0x1234), fixture.client.response.header.id);
                    try testing.expectEqualSlices(
                        u16,
                        &.{ 1, 0, 0, 0 },
                        &fixture.client.response.header.counts,
                    );
                    try testing.expectEqual(null, fixture.client.response.opt);
                    var cursor: usize = 12;
                    const question = try fixture.client.response.readQuestion(&cursor);
                    var name: wire.Name = undefined;
                    try fixture.client.response.name(&name, question.name);
                    try testing.expectEqualSlices(
                        u8,
                        fixture.client.request.name.wire(),
                        name.wire(),
                    );
                    try testing.expectEqual(@as(u16, 28), @intFromEnum(question.kind));
                    try testing.expectEqual(@as(u16, 3), question.class);
                    try testing.expectEqual(null, try fixture.lookup(0));
                }
            }
        }
    }

    // SPEC §3.7, §3.9: local failure neither replaces existing data nor selects stale data.
    test "cache unrepresentable extended errors preserve fresh and stale candidates" {
        for ([_]u16{ 0, 3 }) |rcode| {
            var fixture: test_fixture.Fixture = undefined;
            try fixture.init(testing.allocator, &test_fixture.zone);
            defer fixture.cache.deinit();
            try fixture.response(0x8500 | rcode);
            if (rcode == 0) {
                try fixture.record(1, .answer, 5, 0);
            } else {
                try fixture.record(6, .authority, 5, 5);
            }
            _ = try fixture.forward(0);
            try fixture.response(0x8500);
            const edns: wire.rewrite.Edns = .{ .payload_bytes = 1232, .extended_rcode = 1 };
            try wire.rewrite.writeOpt(&fixture.encoder, &edns);
            for ([_]u64{ 1, 5 }) |now_s| {
                const result = try fixture.forward(now_s);
                try testing.expectEqual(.servfail, result.answer.source);
                try testing.expectEqual(.skipped, result.insertion);
                try fixture.client.response.parse(result.answer.bytes);
                try testing.expectEqual(@as(u16, 2), fixture.client.response.header.bits & 15);
                try testing.expectEqual(null, fixture.client.response.opt);
                if (now_s == 1) {
                    const retained = (try fixture.lookup(now_s)).?;
                    try fixture.ttl(&retained, 4);
                    try testing.expectEqual(rcode, fixture.client.response.header.bits & 15);
                }
            }
            try testing.expectEqual(null, try fixture.lookup(5));
            const stale = try fixture.failure(5);
            try testing.expectEqual(.stale, stale.answer.source);
            try fixture.ttl(&stale.answer, 30);
            try testing.expectEqual(rcode, fixture.client.response.header.bits & 15);
        }
    }

    // SPEC §3.9; RFC 6891 §6.1.3; RFC 7873 §4: EDNS retains all RCODE bits and client COOKIE.
    test "cache extended errors with EDNS retain RCODE and client envelope" {
        for ([_]?test_fixture.resolver.config.Cache{ test_fixture.zone.cache, null }) |settings| {
            var zone = test_fixture.zone;
            zone.cache = settings;
            var fixture: test_fixture.Fixture = undefined;
            try fixture.init(testing.allocator, &zone);
            defer fixture.cache.deinit();
            const cookie = .{ 0, 10, 0, 8 } ++ .{42} ** 8;
            try fixture.client.edns(&cookie);
            for ([_]u8{ 1, 255 }) |extended| {
                for ([_]u16{ 0, 2, 3 }) |low| {
                    try fixture.response(0x8500 | low);
                    const edns: wire.rewrite.Edns = .{
                        .payload_bytes = 1232,
                        .extended_rcode = extended,
                        .options = &(.{ 0, 10, 0, 8 } ++ .{99} ** 8),
                    };
                    try wire.rewrite.writeOpt(&fixture.encoder, &edns);
                    const result = try fixture.forward(0);
                    try testing.expectEqual(.forward, result.answer.source);
                    try testing.expectEqual(.skipped, result.insertion);
                    try fixture.client.response.parse(result.answer.bytes);
                    try testing.expectEqual(low, fixture.client.response.header.bits & 15);
                    const opt = fixture.client.response.records[fixture.client.response.opt.?];
                    try testing.expectEqual(@as(u32, extended), opt.ttl_s >> 24);
                    try testing.expectEqual(@as(u16, 1400), opt.class);
                    try testing.expectEqual(@as(u32, 0x8000), opt.ttl_s & 0xffff);
                    try testing.expectEqualSlices(
                        u8,
                        &cookie,
                        result.answer.bytes[opt.data_start..opt.data_end],
                    );
                    try testing.expectEqual(@as(u16, 0x1234), fixture.client.response.header.id);
                    try testing.expectEqual(null, try fixture.lookup(0));
                }
            }
        }
    }

    // SPEC §3.9: short local SERVFAIL output leaves the stale candidate intact.
    test "cache extended error local encoding failure preserves stale candidate" {
        var fixture: test_fixture.Fixture = undefined;
        try fixture.init(testing.allocator, &test_fixture.zone);
        defer fixture.cache.deinit();
        try fixture.response(0x8500);
        try fixture.record(1, .answer, 5, 0);
        _ = try fixture.forward(0);
        try fixture.response(0x8500);
        const edns: wire.rewrite.Edns = .{ .payload_bytes = 1232, .extended_rcode = 1 };
        try wire.rewrite.writeOpt(&fixture.encoder, &edns);
        const bytes = try fixture.encoder.finish();
        for ([_]usize{ 11, 12 }) |length| {
            try testing.expectError(error.NoSpace, fixture.cache.forward(
                &fixture.client.request,
                bytes,
                5,
                &fixture.workspace,
                fixture.client.output[0..length],
            ));
        }
        const stale = try fixture.failure(5);
        try testing.expectEqual(.stale, stale.answer.source);
        try fixture.ttl(&stale.answer, 30);
    }
};

comptime {
    if (builtin.is_test) _ = ResolverTestsCachePackets;
}

const ResolverTestsCachePackets = struct {
    const testing = std.testing;

    // SPEC §§1.3, 3.7: every class boundary supports allocate/free/reuse without backing growth.
    test "cache packet classes include full DNS size and reuse every boundary" {
        var allocator = testing.FailingAllocator.init(testing.allocator, .{});
        var storage: packets.Storage = undefined;
        try storage.init(allocator.allocator(), 1024 * 1024);
        defer storage.deinit(allocator.allocator());
        allocator.fail_index = allocator.alloc_index;
        for (packets.sizes, 0..) |size, index| {
            const low = if (index == 0) 1 else packets.sizes[index - 1] + 1;
            const high = @min(size, test_fixture.wire.message_bytes_max);
            for ([_]u32{ low, high }) |length| {
                try testing.expectEqual(index, packets.class(length));
                const first = try storage.create(length);
                @memset(first, 42);
                const address = first.ptr;
                const used = storage.fixed.end_index;
                storage.destroy(first, @intCast(index));
                const second = try storage.create(length);
                try testing.expectEqual(address, second.ptr);
                try testing.expectEqual(used, storage.fixed.end_index);
                try testing.expectEqual(length, storage.live_bytes);
                try testing.expectEqual(size, storage.live_class_bytes);
                storage.destroy(second, @intCast(index));
                try testing.expectEqual(0, storage.live_bytes);
                try testing.expectEqual(0, storage.live_class_bytes);
            }
        }
        try testing.expect(!allocator.has_induced_failure);
        try testing.expectEqual(1, allocator.allocations);
        try testing.expect(storage.fixed.end_index <= storage.fixed.buffer.len);
    }

    fn fill(storage: *packets.Storage) !void {
        // The minimum block size bounds successful allocations by backing_bytes / 64.
        for (0..storage.fixed.buffer.len / 64 + 1) |_| {
            _ = storage.create(64) catch return;
        }
        return error.UnboundedStorage;
    }

    // SPEC §3.7: free blocks remain reusable, but classes do not borrow each other's free lists.
    test "cache packet exhaustion and class pressure retain bounded reuse" {
        var storage: packets.Storage = undefined;
        try storage.init(testing.allocator, 64 * 1024);
        defer storage.deinit(testing.allocator);
        const first = try storage.create(64);
        const address = first.ptr;
        try fill(&storage);
        try testing.expectError(error.OutOfMemory, storage.create(64));
        storage.destroy(first, 0);
        try testing.expectError(error.OutOfMemory, storage.create(65535));
        const reused = try storage.create(64);
        try testing.expectEqual(address, reused.ptr);
        storage.destroy(reused, 0);
    }

    // SPEC §§3.7, 3.9: byte exhaustion returns the valid answer and preserves the stale packet.
    test "cache packet pressure preserves stale data and rejects destructive class replacement" {
        var allocator = testing.FailingAllocator.init(testing.allocator, .{});
        var fixture: test_fixture.Fixture = undefined;
        var zone = test_fixture.zone;
        zone.cache.?.packet_bytes_max = 64 * 1024;
        try fixture.init(allocator.allocator(), &zone);
        defer fixture.cache.deinit();
        allocator.fail_index = allocator.alloc_index;
        try fixture.response(0x8500);
        try fixture.record(1, .answer, 5, 0);
        try testing.expectEqual(.stored, (try fixture.forward(0)).insertion);
        const old = fixture.cache.positive.entries.items(.bytes)[0].?;
        try fill(&fixture.cache.packet_storage);
        try fixture.response(0x8503);
        for (0..3) |_| try fixture.record(6, .authority, 60, 60);
        const denied = try fixture.forward(5);
        try testing.expectEqual(.exhausted, denied.insertion);
        try testing.expectEqual(.forward, denied.answer.source);
        try fixture.client.response.parse(denied.answer.bytes);
        try testing.expectEqual(3, fixture.client.response.header.bits & 15);
        try testing.expectEqual(old.ptr, fixture.cache.positive.entries.items(.bytes)[0].?.ptr);
        try testing.expectEqual(null, fixture.cache.denial.first);
        try testing.expectEqual(.stale, (try fixture.failure(5)).answer.source);
        try testing.expect(!allocator.has_induced_failure);
    }

    // SPEC §3.7: same-class refresh and cross-bank transfer succeed even when all blocks are busy.
    test "cache full packet arena refresh eviction and cross bank transfer allocate nothing" {
        var allocator = testing.FailingAllocator.init(testing.allocator, .{});
        var fixture: test_fixture.Fixture = undefined;
        var zone = test_fixture.zone;
        zone.cache.?.capacity = 1;
        zone.cache.?.packet_bytes_max = 64 * 1024;
        try fixture.init(allocator.allocator(), &zone);
        defer fixture.cache.deinit();
        allocator.fail_index = allocator.alloc_index;
        try fixture.response(0x8500);
        try fixture.record(1, .answer, 5, 0);
        _ = try fixture.forward(0);
        const address = fixture.cache.positive.entries.items(.bytes)[0].?.ptr;
        try fill(&fixture.cache.packet_storage);
        for (0..32) |index| {
            try fixture.response(0x8500);
            try fixture.record(1, .answer, 5, 0);
            try testing.expectEqual(.stored, (try fixture.forward(index)).insertion);
            try testing.expectEqual(address, fixture.cache.positive.entries.items(.bytes)[0].?.ptr);
            try testing.expect((try fixture.lookup(index)) != null);
        }
        // SERVFAIL has the same class and transfers this key into the empty denial bank.
        try fixture.response(0x8502);
        try testing.expectEqual(.stored, (try fixture.forward(32)).insertion);
        try testing.expectEqual(null, fixture.cache.positive.first);
        try testing.expectEqual(address, fixture.cache.denial.entries.items(.bytes)[0].?.ptr);
        try fixture.response(0x8500);
        try fixture.record(1, .answer, 5, 0);
        try testing.expectEqual(.stored, (try fixture.forward(33)).insertion);
        try testing.expectEqual(null, fixture.cache.denial.first);
        try fixture.client.init("evicted.", 1, 1);
        try fixture.response(0x8500);
        try fixture.record(1, .answer, 5, 0);
        try testing.expectEqual(.stored, (try fixture.forward(34)).insertion);
        try testing.expectEqual(address, fixture.cache.positive.entries.items(.bytes)[0].?.ptr);
        fixture.cache.positive.remove(&fixture.cache.packet_storage, 0);
        try testing.expectEqual(.stored, (try fixture.forward(35)).insertion);
        try testing.expectEqual(address, fixture.cache.positive.entries.items(.bytes)[0].?.ptr);
        try testing.expect(!allocator.has_induced_failure);
        try testing.expectEqual(5, allocator.allocations);
        try testing.expectEqual(0, allocator.deallocations);
        try testing.expectEqual(0, allocator.resize_index);
    }

    // SPEC §3.7: byte pressure cannot raid unrelated entries in the other bank.
    test "cache class pressure preserves both bank victims and their LRU links" {
        var fixture: test_fixture.Fixture = undefined;
        var zone = test_fixture.zone;
        zone.cache.?.capacity = 1;
        zone.cache.?.packet_bytes_max = 64 * 1024;
        try fixture.init(testing.allocator, &zone);
        defer fixture.cache.deinit();
        try fixture.response(0x8500);
        try fixture.record(1, .answer, 5, 0);
        _ = try fixture.forward(0);
        const positive = fixture.cache.positive.entries.items(.bytes)[0].?;
        try fixture.client.init("denied.example.", 1, 1);
        try fixture.response(0x8503);
        try fixture.record(6, .authority, 5, 5);
        _ = try fixture.forward(0);
        const denial = fixture.cache.denial.entries.items(.bytes)[0].?;
        try fill(&fixture.cache.packet_storage);
        // Drain the already reserved 128-byte class arena as well as the shared backing.
        for (0..1025) |_| {
            _ = fixture.cache.packet_storage.create(128) catch break;
        } else return error.UnboundedStorage;
        try fixture.client.init("replacement.example.", 1, 1);
        try fixture.response(0x8500);
        for (0..3) |_| try fixture.record(1, .answer, 60, 0);
        try testing.expectEqual(.exhausted, (try fixture.forward(5)).insertion);
        try testing.expectEqual(
            positive.ptr,
            fixture.cache.positive.entries.items(.bytes)[0].?.ptr,
        );
        try testing.expectEqual(denial.ptr, fixture.cache.denial.entries.items(.bytes)[0].?.ptr);
        const banks = [_]*@TypeOf(fixture.cache.positive){
            &fixture.cache.positive,
            &fixture.cache.denial,
        };
        for (banks) |bank| {
            try testing.expectEqual(0, bank.first.?);
            try testing.expectEqual(0, bank.last.?);
            try testing.expectEqual(null, bank.entries.items(.previous)[0]);
            try testing.expectEqual(null, bank.entries.items(.next)[0]);
        }
        try fixture.client.init("example.", 1, 1);
        try testing.expectEqual(.stale, (try fixture.failure(5)).answer.source);
        try fixture.client.init("denied.example.", 1, 1);
        try testing.expectEqual(.stale, (try fixture.failure(5)).answer.source);
    }

    // SPEC §§3.7, 3.9: the full 65535-byte DNS message survives storage and cache delivery.
    test "cache packet pool stores and serves the maximum DNS message" {
        var allocator = testing.FailingAllocator.init(testing.allocator, .{});
        var fixture: test_fixture.Fixture = undefined;
        try fixture.init(allocator.allocator(), &test_fixture.zone);
        defer fixture.cache.deinit();
        allocator.fail_index = allocator.alloc_index;
        try fixture.client.init(".", 65280, 1);
        try fixture.response(0x8500);
        const offset = try fixture.encoder.beginRecord(&fixture.client.request.name, &.{
            .owner = 0,
            .kind = @enumFromInt(65280),
            .class = 1,
            .ttl_s = 60,
            .data_start = 0,
            .data_end = 0,
            .section = .answer,
        });
        const padding: [test_fixture.wire.message_bytes_max]u8 = @splat(0);
        try fixture.encoder.bytes(padding[0 .. padding.len - fixture.encoder.cursor]);
        fixture.encoder.endRecord(offset);
        const result = try fixture.forward(0);
        try testing.expectEqual(.stored, result.insertion);
        try testing.expectEqual(65535, result.answer.bytes.len);
        try testing.expectEqual(65535, fixture.cache.packet_storage.live_bytes);
        try testing.expectEqual(65536, fixture.cache.packet_storage.live_class_bytes);
        const hit = (try fixture.lookup(1)).?;
        try testing.expectEqual(65535, hit.bytes.len);
        try fixture.ttl(&hit, 59);
        try testing.expect(!allocator.has_induced_failure);
    }

    // SPEC §§1.3, 5.1: a disabled cache reserves no packet or bank storage.
    test "disabled cache allocates no storage" {
        var allocator = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
        var zone = test_fixture.zone;
        zone.cache = null;
        var cache: test_fixture.cache.Cache = undefined;
        try cache.init(allocator.allocator(), &zone);
        defer cache.deinit();
        try testing.expectEqual(0, allocator.allocations);
        try testing.expectEqual(0, cache.packet_storage.fixed.buffer.len);
        try testing.expect(!allocator.has_induced_failure);
    }
};

comptime {
    if (builtin.is_test) _ = ResolverTestsCacheDname;
}

const ResolverTestsCacheDname = struct {
    const testing = test_fixture.testing;

    fn alias(
        fixture: *test_fixture.Fixture,
        owner: []const u8,
        target: []const u8,
        kind: u16,
    ) !void {
        var name: wire.Name = undefined;
        var destination: wire.Name = undefined;
        try name.fromText(owner);
        try destination.fromText(target);
        const record: wire.Record = .{
            .owner = 0,
            .kind = @enumFromInt(kind),
            .class = 1,
            .ttl_s = 60,
            .data_start = 0,
            .data_end = 0,
            .section = .answer,
        };
        const offset = try fixture.encoder.beginRecord(&name, &record);
        try fixture.encoder.name(&destination, if (kind == 39) .forbidden else .allowed);
        fixture.encoder.endRecord(offset);
    }

    fn authority(fixture: *test_fixture.Fixture) !void {
        var name: wire.Name = undefined;
        try name.fromText("target.");
        const record: wire.Record = .{
            .owner = 0,
            .kind = .soa,
            .class = 1,
            .ttl_s = 60,
            .data_start = 0,
            .data_end = 0,
            .section = .authority,
        };
        const offset = try fixture.encoder.beginRecord(&name, &record);
        try fixture.encoder.name(&name, .allowed);
        try fixture.encoder.name(&name, .allowed);
        for (0..4) |_| try fixture.encoder.number(u32, 0);
        try fixture.encoder.number(u32, 1);
        fixture.encoder.endRecord(offset);
    }

    // SPEC §3.7; RFC 2308 §2.2; RFC 6672 §3: DNAME redirection is not a terminal A answer.
    test "cache DNAME and synthesized CNAME without queried data use denial lifetime" {
        var fixture: test_fixture.Fixture = undefined;
        try fixture.init(testing.allocator, &test_fixture.zone);
        defer fixture.cache.deinit();
        try fixture.client.init("child.example.", 1, 1);
        try fixture.response(0x8500);
        try alias(&fixture, "example.", "target.", 39);
        try alias(&fixture, "child.example.", "child.target.", 5);
        try authority(&fixture);
        const result = try fixture.forward(0);
        try fixture.ttl(&result.answer, 5);
        try testing.expectEqual(null, fixture.cache.positive.first);
        try testing.expect(fixture.cache.denial.first != null);
        try testing.expectEqual(@as(u16, 2), fixture.client.response.header.counts[1]);
        for (fixture.client.response.records[0..3]) |record| {
            try testing.expectEqual(@as(u32, 5), record.ttl_s);
        }
        const hit = (try fixture.lookup(4)).?;
        try fixture.ttl(&hit, 1);
        try testing.expectEqual(null, try fixture.lookup(5));
        const stale = try fixture.failure(5);
        try testing.expectEqual(.stale, stale.answer.source);
        try fixture.ttl(&stale.answer, 30);
    }

    // SPEC §3.7; RFC 6672 §3: actual DNAME/CNAME/ANY answers remain positive despite
    // authority SOA.
    test "cache queried DNAME CNAME and ANY retain positive lifetime" {
        for ([_]u16{ 39, 5, 255 }) |kind| {
            var fixture: test_fixture.Fixture = undefined;
            try fixture.init(testing.allocator, &test_fixture.zone);
            defer fixture.cache.deinit();
            try fixture.client.init(if (kind == 5) "child.example." else "example.", kind, 1);
            try fixture.response(0x8500);
            try alias(&fixture, "example.", "target.", 39);
            if (kind == 5) try alias(&fixture, "child.example.", "child.target.", 5);
            try authority(&fixture);
            const result = try fixture.forward(0);
            try fixture.ttl(&result.answer, 60);
            try testing.expect(fixture.cache.positive.first != null);
            try testing.expectEqual(null, fixture.cache.denial.first);
            const hit = (try fixture.lookup(59)).?;
            try fixture.ttl(&hit, 1);
            try testing.expectEqual(null, try fixture.lookup(60));
        }
    }
};

comptime {
    if (builtin.is_test) _ = ResolverTestsCacheBoundaries;
}

const ResolverTestsCacheBoundaries = struct {
    const testing = test_fixture.testing;

    // SPEC §3.7; RFC 2308 §5: default denial cap, stale TTL 30, and fresh answer replacement.
    test "denial default maximum stale and positive replacement" {
        var fixture: test_fixture.Fixture = undefined;
        try fixture.init(testing.allocator, &test_fixture.zone);
        defer fixture.cache.deinit();
        try fixture.response(0x8503);
        try fixture.record(6, .authority, 5000, 4000);
        const denied = try fixture.forward(0);
        try fixture.ttl(&denied.answer, 1800);
        const stale = try fixture.failure(1800);
        try testing.expectEqual(.stale, stale.answer.source);
        try fixture.ttl(&stale.answer, 30);
        try testing.expectEqual(@as(u16, 3), fixture.client.response.header.bits & 15);
        try fixture.response(0x8500);
        try fixture.record(1, .answer, 60, 0);
        _ = try fixture.forward(1801);
        const hit = (try fixture.lookup(1802)).?;
        try fixture.ttl(&hit, 59);
        try testing.expectEqual(@as(u16, 0), fixture.client.response.header.bits & 15);
        for (fixture.cache.denial.entries.items(.bytes)) |bytes| {
            try testing.expectEqual(null, bytes);
        }
    }

    // SPEC §3.7, §3.9; RFC 7873 §4: DO-clear EDNS shares plain data, not another
    // client's COOKIE.
    test "cache plain client omits stored EDNS and binary name dots cannot alias" {
        var fixture: test_fixture.Fixture = undefined;
        try fixture.init(testing.allocator, &test_fixture.zone);
        defer fixture.cache.deinit();
        try fixture.client.init("a.example.", 1, 3);
        const cookie = .{ 0, 10, 0, 40 } ++ .{42} ** 40;
        try fixture.client.edns(&cookie);
        fixture.client.query.records[fixture.client.query.opt.?].ttl_s = 0;
        try fixture.response(0x8500);
        try fixture.record(1, .answer, 60, 0);
        const edns: wire.rewrite.Edns = .{ .payload_bytes = 1232, .options = &cookie };
        try wire.rewrite.writeOpt(&fixture.encoder, &edns);
        _ = try fixture.forward(0);
        try fixture.client.init("A.EXAMPLE.", 1, 3);
        const hit = (try fixture.lookup(0)).?;
        try fixture.ttl(&hit, 60);
        try testing.expectEqual(null, fixture.client.response.opt);
        try testing.expectEqual(@as(u16, 3), fixture.client.response.records[0].class);
        fixture.client.request.name.length = 11;
        @memcpy(fixture.client.request.name.bytes[0..11], "\x09a.example\x00");
        try testing.expectEqual(null, try fixture.lookup(0));
    }

    // SPEC §3.7: positive and denial capacity are separate, including SERVFAIL in the denial bank.
    test "denial churn cannot evict a full positive bank" {
        var fixture: test_fixture.Fixture = undefined;
        try fixture.init(testing.allocator, &test_fixture.zone);
        defer fixture.cache.deinit();
        for ([_][]const u8{ "one.", "two." }) |name| {
            try fixture.client.init(name, 1, 1);
            try fixture.response(0x8500);
            try fixture.record(1, .answer, 60, 0);
            _ = try fixture.forward(0);
        }
        for ([_][]const u8{ "denied-one.", "denied-two.", "denied-three." }) |name| {
            try fixture.client.init(name, 1, 1);
            _ = try fixture.failure(0);
        }
        for ([_][]const u8{ "one.", "two." }) |name| {
            try fixture.client.init(name, 1, 1);
            try testing.expect((try fixture.lookup(0)) != null);
        }
        try fixture.client.init("denied-one.", 1, 1);
        try testing.expectEqual(null, try fixture.lookup(0));
    }

    // SPEC §3.7: TTL and clock arithmetic widen instead of wrapping at u32/u64 limits.
    test "maximum TTL aging does not wrap and zero positive TTL can expire immediately" {
        var fixture: test_fixture.Fixture = undefined;
        var zone = test_fixture.zone;
        zone.cache.?.max_ttl_s = std.math.maxInt(u32);
        try fixture.init(testing.allocator, &zone);
        defer fixture.cache.deinit();
        try fixture.response(0x8500);
        try fixture.record(1, .answer, std.math.maxInt(u32), 0);
        _ = try fixture.forward(0);
        const hit = (try fixture.lookup(std.math.maxInt(u32) - 1)).?;
        try fixture.ttl(&hit, 1);
        try testing.expectEqual(null, try fixture.lookup(std.math.maxInt(u32)));
        const stale = try fixture.failure(@as(u64, std.math.maxInt(u32)) + 1);
        try fixture.ttl(&stale.answer, 30);
        fixture.cache.settings.?.min_ttl_s = 0;
        try fixture.response(0x8500);
        try fixture.record(1, .answer, 0, 0);
        const result = try fixture.forward(std.math.maxInt(u64));
        try fixture.ttl(&result.answer, 0);
        try testing.expectEqual(null, try fixture.lookup(std.math.maxInt(u64)));
        try testing.expectEqual(.stale, (try fixture.failure(std.math.maxInt(u64))).answer.source);
    }

    // SPEC §3.7; RFC 2308 §2.2: an actual answer to CNAME/ANY is positive, not a
    // CNAME-chain denial.
    test "queried CNAME and ANY remain positive with authority SOA" {
        var fixture: test_fixture.Fixture = undefined;
        try fixture.init(testing.allocator, &test_fixture.zone);
        defer fixture.cache.deinit();
        for ([_]u16{ 5, 255 }) |kind| {
            try fixture.client.init("example.", kind, 1);
            try fixture.response(0x8500);
            try fixture.record(5, .answer, 60, 0);
            try fixture.record(6, .authority, 60, 1);
            const result = try fixture.forward(0);
            try fixture.ttl(&result.answer, 60);
            const hit = (try fixture.lookup(59)).?;
            try fixture.ttl(&hit, 1);
        }
    }
};

comptime {
    if (builtin.is_test) _ = ResolverTestsCacheStress;
}

const ResolverTestsCacheStress = struct {
    const testing = test_fixture.testing;
    const capacity = 128;

    fn identity(fixture: *test_fixture.Fixture, key: u16, id: u16) !void {
        var text: [64]u8 = undefined;
        const name = try std.fmt.bufPrint(&text, "key{d}.stress.example.", .{key / 8});
        try fixture.client.init(name, if (key & 1 == 0) 1 else 255, if (key & 2 == 0) 1 else 3);
        if (key & 4 != 0) try fixture.client.edns(&.{});
        fixture.client.query.header.id = id;
    }

    fn insert(fixture: *test_fixture.Fixture, bank: enum { positive, denial }) !void {
        try fixture.response(if (bank == .positive) 0x8500 else 0x8503);
        if (bank == .positive) {
            try fixture.record(1, .answer, 60, 0);
        } else try fixture.record(6, .authority, 60, 60);
        const result = try fixture.forward(100);
        try testing.expectEqual(.stored, result.insertion);
        try testing.expectEqual(.forward, result.answer.source);
    }

    fn hit(fixture: *test_fixture.Fixture, now_s: u64, rcode: u16) !void {
        const result = (try fixture.lookup(now_s)) orelse return error.UnexpectedMiss;
        try testing.expectEqual(.cache, result.source);
        try fixture.ttl(&result, @intCast(160 - now_s));
        const packet = &fixture.client.response;
        try testing.expectEqual(fixture.client.query.header.id, packet.header.id);
        try testing.expectEqual(rcode, packet.header.bits & 15);
        var cursor: usize = 12;
        const question = try packet.readQuestion(&cursor);
        var name: test_fixture.wire.Name = undefined;
        try packet.name(&name, question.name);
        try testing.expectEqualSlices(u8, fixture.client.request.name.wire(), name.wire());
        try testing.expectEqual(fixture.client.request.kind, question.kind);
        try testing.expectEqual(fixture.client.request.class, question.class);
        try testing.expectEqual(fixture.client.query.opt != null, packet.opt != null);
        if (packet.opt) |index| try testing.expectEqual(0x8000, packet.records[index].ttl_s);
        const record = packet.records[0];
        if (rcode == 0)
            try testing.expectEqualSlices(
                u8,
                &.{ 192, 0, 2, 1 },
                result.bytes[record.data_start..record.data_end],
            );
    }

    // SPEC §§1.3, 3.7, RFC 6891 §6.1.4: full-capacity mixed keys preserve LRU, IDs,
    // TTLs, and DO.
    test "cache stress full capacity mixed keys and repeated LRU churn without hit allocation" {
        var allocator = testing.FailingAllocator.init(testing.allocator, .{});
        var fixture: test_fixture.Fixture = undefined;
        var zone = test_fixture.zone;
        zone.cache = .{ .capacity = capacity };
        try fixture.init(allocator.allocator(), &zone);
        defer fixture.cache.deinit();
        // The independent model stores oldest first, without the cache's intrusive links.
        var order: [capacity]u16 = undefined;
        for (&order, 0..) |*key, index| {
            key.* = @intCast(index);
            try identity(&fixture, key.*, @intCast(index));
            try insert(&fixture, .positive);
        }
        for (0..16) |round| {
            const allocations = allocator.alloc_index;
            allocator.fail_index = allocations;
            for (0..32) |probe| {
                const position = (round * 17 + probe * 31) % capacity;
                const key = order[position];
                try identity(&fixture, key, @intCast(1000 + round * 32 + probe));
                try hit(&fixture, 101 + round, 0);
                @memmove(order[position .. capacity - 1], order[position + 1 ..]);
                order[capacity - 1] = key;
            }
            try testing.expectEqual(allocations, allocator.alloc_index);
            try testing.expect(!allocator.has_induced_failure);
            allocator.fail_index = std.math.maxInt(usize);
            const evicted = order[0];
            const next: u16 = @intCast(capacity + round);
            try identity(&fixture, next, @intCast(2000 + round));
            try insert(&fixture, .positive);
            @memmove(order[0 .. capacity - 1], order[1..]);
            order[capacity - 1] = next;
            try identity(&fixture, evicted, 3000);
            try testing.expectEqual(null, try fixture.lookup(101 + round));
        }
        for (order) |key| {
            try identity(&fixture, key, key + 4000);
            try hit(&fixture, 117, 0);
        }
    }

    // SPEC §3.7: cross-bank replacement at capacity removes old keys without shadow entries.
    test "cache stress full positive and denial banks replace every entry twice" {
        var fixture: test_fixture.Fixture = undefined;
        var zone = test_fixture.zone;
        zone.cache = .{ .capacity = capacity };
        try fixture.init(testing.allocator, &zone);
        defer fixture.cache.deinit();
        for (0..capacity * 2) |index| {
            try identity(&fixture, @intCast(index), @intCast(index));
            try insert(&fixture, if (index < capacity) .positive else .denial);
        }
        for (0..capacity) |index| {
            try identity(&fixture, @intCast(index), @intCast(1000 + index));
            try hit(&fixture, 101, 0);
            try insert(&fixture, .denial);
            try hit(&fixture, 102, 3);
            try identity(&fixture, @intCast(capacity + index), 2000);
            try testing.expectEqual(null, try fixture.lookup(102));
        }
        for (fixture.cache.positive.entries.items(.bytes)) |bytes| {
            try testing.expectEqual(null, bytes);
        }
        for (0..capacity) |index| {
            try identity(&fixture, @intCast(index), @intCast(3000 + index));
            try insert(&fixture, .positive);
            try hit(&fixture, 103, 0);
        }
        for (fixture.cache.denial.entries.items(.bytes)) |bytes| {
            try testing.expectEqual(null, bytes);
        }
    }
};
