//! DNS packet classes share one fixed backing allocation.
//! Class pools and free-list nodes stay inside that allocation. Classes never rebalance.
const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const wire = @import("../wire.zig");
const Pool = @import("stdx").heap.SizeClassPool(&.{
    64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536,
});

pub const sizes = Pool.sizes;

pub const Storage = struct {
    pool: Pool = .init(&.{}),

    pub fn init(self: *Storage, allocator: Allocator, limit: u32) error{OutOfMemory}!void {
        self.pool = .init(try allocator.alloc(u8, limit));
    }

    pub fn deinit(self: *Storage, allocator: Allocator) void {
        // The backing owns every pool arena. Freeing it releases all blocks, so
        // the one-shot storage skips SizeClassPool.deinit and its all-freed check.
        allocator.free(self.pool.backing);
        self.* = undefined;
    }

    pub fn create(self: *Storage, length: usize) error{OutOfMemory}![]u8 {
        return self.pool.create(length);
    }

    pub fn copy(self: *Storage, bytes: []const u8) error{OutOfMemory}![]u8 {
        const owned = try self.create(bytes.len);
        @memcpy(owned, bytes);
        return owned;
    }

    pub fn destroy(self: *Storage, bytes: []u8) void {
        self.pool.destroy(bytes);
    }

    /// Transfer a block to a new requested length in the same class.
    pub fn reuse(self: *Storage, bytes: []u8, length: usize) []u8 {
        assert(class(bytes.len) == class(length));
        self.pool.live_bytes -= bytes.len;
        self.pool.live_bytes += length;
        return bytes.ptr[0..length];
    }

    pub fn liveBytes(self: *const Storage) usize {
        return self.pool.live_bytes;
    }

    pub fn liveClassBytes(self: *const Storage) usize {
        return self.pool.live_class_bytes;
    }

    pub fn reservedBytes(self: *const Storage) usize {
        return self.pool.backing.len;
    }

    pub fn consumedBytes(self: *const Storage) usize {
        return self.pool.fixed.end_index;
    }
};

comptime {
    assert(@sizeOf(Storage) <= 512);
}

pub fn class(length: usize) ?u8 {
    assert(length > 0);
    assert(length <= wire.message_bytes_max);
    for (sizes, 0..) |size, index| {
        if (length <= size) return @intCast(index);
    }
    return null;
}
