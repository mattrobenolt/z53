//! DNS packet classes share one fixed backing allocation (#1).
//! Pool arenas and free-list nodes stay inside that allocation. Classes never rebalance.
const std = @import("std");
const wire = @import("../wire.zig");

pub const sizes = [_]u32{ 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536 };
const Pools = blk: {
    var types: [sizes.len]type = undefined;
    for (sizes, &types) |size, *kind| kind.* = std.heap.MemoryPool([size]u8);
    break :blk std.meta.Tuple(&types);
};

pub const Storage = struct {
    fixed: std.heap.FixedBufferAllocator = .init(&.{}),
    pools: Pools = undefined,
    live_bytes: u32 = 0,
    live_class_bytes: u32 = 0,

    pub fn init(self: *Storage, allocator: std.mem.Allocator, limit: u32) error{OutOfMemory}!void {
        self.* = .{ .fixed = .init(try allocator.alloc(u8, limit)) };
        inline for (&self.pools) |*pool| pool.* = .empty;
    }

    pub fn deinit(self: *Storage, allocator: std.mem.Allocator) void {
        // The backing allocation owns every pool arena, including its metadata.
        allocator.free(self.fixed.buffer);
        self.* = undefined;
    }

    pub fn create(self: *Storage, length: usize) error{OutOfMemory}![]u8 {
        const selected = class(length);
        inline for (&self.pools, 0..) |*pool, index| {
            if (selected == index) {
                const block = try pool.create(self.fixed.allocator());
                self.live_bytes += @intCast(length);
                self.live_class_bytes += sizes[index];
                return block[0..length];
            }
        }
        unreachable;
    }

    pub fn copy(self: *Storage, bytes: []const u8) error{OutOfMemory}![]u8 {
        const owned = try self.create(bytes.len);
        @memcpy(owned, bytes);
        return owned;
    }

    pub fn destroy(self: *Storage, bytes: []u8, selected: u8) void {
        std.debug.assert(selected == class(bytes.len));
        inline for (&self.pools, 0..) |*pool, index| {
            if (selected == index) {
                pool.destroy(@ptrCast(@alignCast(bytes.ptr)));
                self.live_bytes -= @intCast(bytes.len);
                self.live_class_bytes -= sizes[index];
                return;
            }
        }
        unreachable;
    }
};

comptime {
    std.debug.assert(@sizeOf(Storage) <= 512);
}

pub fn class(length: usize) u8 {
    std.debug.assert(length > 0);
    std.debug.assert(length <= wire.message_bytes_max);
    for (sizes, 0..) |size, index| {
        if (length <= size) return @intCast(index);
    }
    unreachable;
}
