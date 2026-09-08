//! #1: bounded append-only storage. Clear the active length without touching retained elements.
const std = @import("std");

pub fn ArrayBuffer(comptime T: type, comptime capacity_max: usize) type {
    return struct {
        pub const Index = std.math.IntFittingRange(0, capacity_max);
        pub const capacity = capacity_max;
        pub const empty: Self = .{ .buffer = undefined, .len = 0 };
        const Self = @This();

        buffer: [capacity]T,
        len: Index,

        pub fn clear(self: *Self) void {
            self.len = 0;
        }

        pub fn slice(self: *Self) []T {
            return self.buffer[0..self.len];
        }

        pub fn constSlice(self: *const Self) []const T {
            return self.buffer[0..self.len];
        }

        pub fn unusedCapacitySlice(self: *Self) []T {
            return self.buffer[self.len..];
        }

        pub fn remainingCapacity(self: *const Self) Index {
            return @intCast(capacity - self.len);
        }

        pub fn append(self: *Self, item: T) error{NoSpaceLeft}!void {
            if (self.remainingCapacity() == 0) return error.NoSpaceLeft;
            self.appendAssumeCapacity(item);
        }

        /// Only a caller with a proven bound can bypass the capacity error.
        pub fn appendAssumeCapacity(self: *Self, item: T) void {
            std.debug.assert(self.len < capacity);
            self.buffer[self.len] = item;
            self.len += 1;
        }

        pub fn appendSlice(self: *Self, items: []const T) error{NoSpaceLeft}!void {
            if (items.len > self.remainingCapacity()) return error.NoSpaceLeft;
            @memcpy(self.unusedCapacitySlice()[0..items.len], items);
            self.len = @intCast(@as(usize, self.len) + items.len);
        }
    };
}
