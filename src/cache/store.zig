//! Fixed entry arrays with intrusive LRU links. Only insertion allocates packet bytes.
const std = @import("std");
const wire = @import("../wire.zig");
const resolver = @import("../resolver.zig");

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

    fn equal(self: *const Key, other: *const Key) bool {
        if (self.kind != other.kind) return false;
        if (self.class != other.class) return false;
        if (self.dnssec != other.dnssec) return false;
        return self.name.equal(&other.name);
    }
};

pub const Entry = struct {
    key: Key = undefined,
    bytes: ?[]u8 = null,
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

pub const Bank = struct {
    entries: []Entry = &.{},
    first: ?u32 = null,
    last: ?u32 = null,

    pub fn deinit(self: *Bank, allocator: std.mem.Allocator) void {
        for (self.entries) |entry| if (entry.bytes) |bytes| allocator.free(bytes);
        allocator.free(self.entries);
        self.* = undefined;
    }

    pub fn find(self: *const Bank, key: *const Key) ?u32 {
        for (self.entries, 0..) |*entry, index| {
            if (entry.bytes == null) continue;
            if (entry.key.equal(key)) return @intCast(index);
        }
        return null;
    }

    pub fn remove(self: *Bank, allocator: std.mem.Allocator, index: u32) void {
        self.unlink(index);
        allocator.free(self.entries[index].bytes.?);
        self.entries[index] = .{};
    }

    pub fn touch(self: *Bank, index: u32) void {
        self.unlink(index);
        self.prepend(index);
    }

    pub fn slot(self: *const Bank, key: *const Key) u32 {
        if (self.find(key)) |index| return index;
        for (self.entries, 0..) |entry, index| {
            if (entry.bytes == null) return @intCast(index);
        }
        return self.last.?;
    }

    pub fn prepend(self: *Bank, index: u32) void {
        std.debug.assert(index < self.entries.len);
        const entry = &self.entries[index];
        std.debug.assert(entry.bytes != null);
        entry.previous = null;
        entry.next = self.first;
        if (self.first) |first| self.entries[first].previous = index else self.last = index;
        self.first = index;
    }

    fn unlink(self: *Bank, index: u32) void {
        std.debug.assert(index < self.entries.len);
        std.debug.assert(self.first != null);
        std.debug.assert(self.last != null);
        const entry = &self.entries[index];
        std.debug.assert(entry.bytes != null);
        if (entry.previous) |previous| {
            self.entries[previous].next = entry.next;
        } else self.first = entry.next;
        if (entry.next) |next| {
            self.entries[next].previous = entry.previous;
        } else self.last = entry.previous;
    }
};
