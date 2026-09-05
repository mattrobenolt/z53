//! One cache per routed zone. All methods are synchronous on one event thread.
//! Output, request bytes and workspace must be disjoint. Delivery is full-size TCP;
//! the runtime applies rotation and client UDP limits afterward, never before insertion.
const std = @import("std");
const resolver = @import("resolver.zig");
const wire = @import("wire.zig");
const config = @import("config.zig");
const store = @import("cache/store.zig");
const policy = @import("cache/policy.zig");
pub const Entry = store.Entry;
pub const Insertion = enum { stored, skipped, exhausted };
pub const Result = struct { answer: resolver.Answer, insertion: Insertion };
pub const Workspace = struct {
    packet: wire.Packet,
    rewrite: wire.rewrite.Workspace,
    storage: [wire.message_bytes_max]u8,
};

pub const Cache = struct {
    allocator: std.mem.Allocator,
    settings: ?config.Cache,
    grace_s: u32,
    positive: store.Bank = .{},
    denial: store.Bank = .{},

    /// The validated zone supplies bounds. Failure invalidates self and releases owned storage.
    pub fn init(
        self: *Cache,
        allocator: std.mem.Allocator,
        zone: *const config.Zone,
    ) error{OutOfMemory}!void {
        self.* = .{ .allocator = allocator, .settings = zone.cache, .grace_s = zone.serve_stale_s };
        const settings = self.settings orelse return;
        std.debug.assert(settings.capacity > 0);
        std.debug.assert(settings.capacity <= config.cache_capacity_max);
        std.debug.assert(settings.min_ttl_s <= settings.max_ttl_s);
        std.debug.assert(settings.denialMaximum() >= 5);
        self.positive.entries = try allocator.alloc(Entry, settings.capacity);
        @memset(self.positive.entries, .{});
        errdefer self.positive.deinit(allocator);
        self.denial.entries = try allocator.alloc(Entry, settings.capacity);
        @memset(self.denial.entries, .{});
    }

    pub fn deinit(self: *Cache) void {
        self.positive.deinit(self.allocator);
        self.denial.deinit(self.allocator);
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
            const entry = &bank.entries[index];
            if (entry.age(now_s) >= entry.lifetime_s) return null;
            const answer = try serve(entry, request, now_s, workspace, output, .cache);
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
        try workspace.packet.parse(response);
        if (request.packet.opt == null) {
            if (workspace.packet.opt) |index| {
                if (workspace.packet.records[index].ttl_s >> 24 != 0) {
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
        var key: store.Key = undefined;
        key.init(request);
        const insertion = self.insert(&key, bytes, now_s, &value) catch .exhausted;
        return .{ .answer = answer, .insertion = insertion };
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
        var key: store.Key = undefined;
        key.init(request);
        for ([_]*store.Bank{ &self.positive, &self.denial }) |bank| {
            const index = bank.find(&key) orelse continue;
            if (!bank.entries[index].stale(now_s, self.grace_s)) continue;
            const answer = try serve(
                &bank.entries[index],
                request,
                now_s,
                workspace,
                output,
                .stale,
            );
            bank.touch(index);
            return .{ .answer = answer, .insertion = .skipped };
        }
        var failure: [512]u8 = undefined;
        const header: wire.Header = .{
            .id = request.packet.header.id,
            .bits = (request.packet.header.bits & 0x0110) | 0x8082,
        };
        const encoder = &workspace.rewrite.encoder;
        try encoder.init(&failure, &header);
        try encoder.question(&request.name, request.kind, request.class);
        var result = try self.forward(request, try encoder.finish(), now_s, workspace, output);
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
        std.debug.assert(bytes.len <= wire.message_bytes_max);
        // Allocate first: failure cannot evict useful data or a stale candidate.
        const owned = try self.allocator.dupe(u8, bytes);
        const bank = if (selected.bank == .positive) &self.positive else &self.denial;
        const other = if (selected.bank == .positive) &self.denial else &self.positive;
        const index = bank.slot(key);
        if (bank.entries[index].bytes != null) bank.remove(self.allocator, index);
        if (other.find(key)) |old| other.remove(self.allocator, old);
        bank.entries[index] = .{
            .key = key.*,
            .bytes = owned,
            .inserted_s = now_s,
            .lifetime_s = selected.lifetime_s,
            .category = if (selected.category == .answer) .answer else .failure,
        };
        bank.prepend(index);
        return .stored;
    }
};

/// RFC 6891 §6.1.3: a client without OPT cannot receive an extended RCODE.
/// This local failure bypasses both cache publication and terminal transport handling.
fn localFailure(
    request: *const resolver.Request,
    encoder: *wire.Encoder,
    output: []u8,
) wire.Error!Result {
    std.debug.assert(request.packet.opt == null);
    const header: wire.Header = .{
        .id = request.packet.header.id,
        .bits = (request.packet.header.bits & 0x0110) | 0x8082,
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
        if (record.kind == 41) continue;
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
    var cookie: [44]u8 = undefined;
    var edns: wire.rewrite.Edns = .{ .payload_bytes = 512 };
    var settings: wire.rewrite.Settings = .{
        .id = request.packet.header.id,
        .question = .{ .name = &request.name, .kind = request.kind, .class = request.class },
        .opt = .omit,
    };
    if (request.packet.opt) |index| {
        edns.payload_bytes = request.packet.records[index].class;
        edns.flags = @as(u16, @truncate(request.packet.records[index].ttl_s)) & 0x8000;
        edns.options = try wire.rewrite.responseOptions(request.packet, &cookie);
        if (workspace.packet.opt) |upstream| {
            edns.extended_rcode = @truncate(workspace.packet.records[upstream].ttl_s >> 24);
        }
        settings.opt = .{ .replace = &edns };
    }
    return .{
        .bytes = try workspace.rewrite.rewrite(&workspace.packet, output, &settings),
        .source = source,
    };
}
