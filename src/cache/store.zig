//! Fixed stdlib columns retain stable slots and intrusive LRU links (#1).
//! Packet ownership belongs to the cache's bounded size-class storage.
const std = @import("std");
const wire = @import("../wire.zig");
const resolver = @import("../resolver.zig");
const packets = @import("packets.zig");

pub const Key = struct {
    name: wire.Name,
    kind: u16,
    class: u16,
    dnssec: enum { ordinary, requested },

    pub fn init(self: *Key, request: *const resolver.Request) void {
        self.name = request.name;
        self.kind = request.kind;
        self.class = request.class;
        self.dnssec = .ordinary;
        if (request.packet.opt) |index| {
            if (request.packet.records[index].ttl_s & 0x8000 != 0) self.dnssec = .requested;
        }
    }

    pub fn fingerprint(self: *const Key) u64 {
        var canonical: [260]u8 = undefined;
        const length: usize = self.name.length;
        // Label lengths are below ASCII letters. Fold data only through the initialized name.
        for (self.name.wire(), canonical[0..length]) |byte, *target| {
            target.* = std.ascii.toLower(byte);
        }
        std.mem.writeInt(u16, canonical[length..][0..2], self.kind, .little);
        std.mem.writeInt(u16, canonical[length + 2 ..][0..2], self.class, .little);
        canonical[length + 4] = @intFromEnum(self.dnssec);
        // Zero denotes an empty slot, never a valid fingerprint. Equality resolves collisions.
        // Zero marks vacant columns. The hash index needs entropy in the low bits.
        const value = std.hash.Wyhash.hash(0, canonical[0 .. length + 5]);
        return if (value == 0) 1 else value;
    }

    fn equal(self: *const Key, other: *const Key) bool {
        if (self.kind != other.kind) return false;
        if (self.class != other.class) return false;
        if (self.dnssec != other.dnssec) return false;
        return self.name.equal(&other.name);
    }
};

pub const Entry = struct {
    key: Key = undefined,
    fingerprint: u64 = 0,
    bytes: ?[]u8 = null,
    packet_class: u8 = 0,
    inserted_s: u64 = 0,
    lifetime_s: u32 = 0,
    category: enum { answer, failure } = .answer,
    previous: ?u32 = null,
    next: ?u32 = null,

    pub fn age(self: *const Entry, now_s: u64) u64 {
        // The event thread supplies monotonic whole seconds, not wall-clock time.
        std.debug.assert(now_s >= self.inserted_s);
        return now_s - self.inserted_s;
    }

    pub fn stale(self: *const Entry, now_s: u64, grace_s: u32) bool {
        if (grace_s == 0) return false;
        if (self.category == .failure) return false;
        const elapsed_s = self.age(now_s);
        if (elapsed_s < self.lifetime_s) return false;
        return elapsed_s - self.lifetime_s < grace_s;
    }
};

pub const IndexContext = struct {
    fingerprints: []const u64,

    pub fn hash(self: IndexContext, index: u32) u64 {
        return self.fingerprints[index];
    }

    pub fn eql(_: IndexContext, source: u32, target: u32) bool {
        return source == target;
    }
};

pub const LookupContext = struct {
    bank: *const Bank,

    pub fn hash(_: LookupContext, key: *const Key) u64 {
        return key.fingerprint();
    }

    pub fn eql(self: LookupContext, key: *const Key, index: u32) bool {
        return self.bank.entries.items(.key)[index].equal(key);
    }
};

pub const Bank = struct {
    pub const Context = IndexContext;

    entries: std.MultiArrayList(Entry) = .empty,
    index: std.HashMapUnmanaged(u32, void, IndexContext, 80) = .empty,
    index_removals: u32 = 0,
    first: ?u32 = null,
    last: ?u32 = null,

    pub fn init(self: *Bank, allocator: std.mem.Allocator, capacity: u32) error{OutOfMemory}!void {
        self.* = .{};
        try self.entries.setCapacity(allocator, capacity);
        errdefer self.entries.deinit(allocator);
        self.entries.len = capacity;
        for (0..capacity) |index| self.entries.set(index, .{});
        try self.index.ensureTotalCapacityContext(allocator, capacity, self.indexContext());
    }

    pub fn deinit(self: *Bank, allocator: std.mem.Allocator) void {
        self.index.deinit(allocator);
        self.entries.deinit(allocator);
        self.* = undefined;
    }

    pub fn find(self: *const Bank, key: *const Key) ?u32 {
        return self.index.getKeyAdapted(key, LookupContext{ .bank = self });
    }

    /// Publish into an empty stable slot. Fixtures use this same metadata path.
    pub fn put(self: *Bank, index: u32, entry: *const Entry) void {
        std.debug.assert(self.entries.items(.bytes)[index] == null);
        std.debug.assert(entry.bytes != null);
        self.entries.set(index, entry.*);
        self.entries.items(.fingerprint)[index] = entry.key.fingerprint();
        // Each occupied slot owns one map key. Replacement removes its old key first.
        self.index.putAssumeCapacityNoClobberContext(index, {}, self.indexContext());
        self.prepend(index);
    }

    pub fn remove(self: *Bank, storage: *packets.Storage, index: u32) void {
        self.unlink(index);
        self.removeIndex(index);
        storage.destroy(
            self.entries.items(.bytes)[index].?,
            self.entries.items(.packet_class)[index],
        );
        self.entries.set(index, .{});
    }

    /// Transfer a block only after all fallible response work succeeds.
    pub fn take(self: *Bank, index: u32) []u8 {
        const bytes = self.entries.items(.bytes)[index].?;
        self.unlink(index);
        self.removeIndex(index);
        self.entries.set(index, .{});
        return bytes;
    }

    pub fn touch(self: *Bank, index: u32) void {
        self.unlink(index);
        self.prepend(index);
    }

    pub fn slot(self: *const Bank, key: *const Key) u32 {
        if (self.find(key)) |index| return index;
        if (self.index.count() == self.entries.len) return self.last.?;
        if (std.mem.findScalar(u64, self.entries.items(.fingerprint), 0)) |index| {
            return @intCast(index);
        }
        unreachable;
    }

    fn removeIndex(self: *Bank, index: u32) void {
        const removed = self.index.removeContext(index, self.indexContext());
        std.debug.assert(removed);
        self.index_removals += 1;
        // A subsequent insertion can consume a free bucket instead of the new tombstone.
        // Rehash before half the reserved spare buckets become tombstones.
        const limit = (self.index.capacity() - self.entries.len) / 2;
        if (self.index_removals < limit) return;
        self.index.rehash(self.indexContext());
        self.index_removals = 0;
    }

    fn indexContext(self: *const Bank) IndexContext {
        return .{ .fingerprints = self.entries.items(.fingerprint) };
    }

    fn prepend(self: *Bank, index: u32) void {
        std.debug.assert(index < self.entries.len);
        const columns = self.entries.slice();
        std.debug.assert(columns.items(.bytes)[index] != null);
        columns.items(.previous)[index] = null;
        columns.items(.next)[index] = self.first;
        if (self.first) |first| columns.items(.previous)[first] = index else self.last = index;
        self.first = index;
    }

    fn unlink(self: *Bank, index: u32) void {
        std.debug.assert(index < self.entries.len);
        std.debug.assert(self.first != null);
        std.debug.assert(self.last != null);
        const columns = self.entries.slice();
        std.debug.assert(columns.items(.bytes)[index] != null);
        const previous = columns.items(.previous)[index];
        const next = columns.items(.next)[index];
        if (previous) |value| {
            columns.items(.next)[value] = next;
        } else self.first = next;
        if (next) |value| {
            columns.items(.previous)[value] = previous;
        } else self.last = previous;
    }
};
