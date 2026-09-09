//! Bounded append-only storage. Clear the active length without touching retained elements.
const std = @import("std");
const testing = std.testing;

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

// SPEC §§1.10, 1.11: a bounded buffer retains dirty storage across logical resets.
test "array buffer clear retains backing storage and exposes only live elements" {
    var buffer: ArrayBuffer(u8, 7) = .empty;
    @memset(&buffer.buffer, 0xa5);
    try buffer.appendSlice("old");
    const retained = buffer.buffer;
    buffer.clear();
    try testing.expectEqual(0, buffer.len);
    try testing.expectEqual(7, buffer.remainingCapacity());
    try testing.expectEqualSlices(u8, &retained, &buffer.buffer);
    try testing.expectEqual(0, buffer.constSlice().len);
    try buffer.append('x');
    try testing.expectEqualSlices(u8, "x", buffer.constSlice());
    buffer.slice()[0] = 'y';
    try testing.expectEqualSlices(u8, "y", buffer.constSlice());
    try testing.expectEqual(6, buffer.unusedCapacitySlice().len);
}

// SPEC §3.9: capacity checks precede narrow index conversion and preserve existing elements.
test "array buffer overflow preserves contents at non power of two capacity" {
    var buffer: ArrayBuffer(u8, 7) = .empty;
    try buffer.appendSlice("1234567");
    try testing.expectError(error.NoSpaceLeft, buffer.append('x'));
    try testing.expectError(error.NoSpaceLeft, buffer.appendSlice("x"));
    try testing.expectEqualSlices(u8, "1234567", buffer.constSlice());
    buffer.clear();
    const oversized: [256]u8 = @splat(0);
    try testing.expectError(error.NoSpaceLeft, buffer.appendSlice(&oversized));
    try testing.expectEqual(0, buffer.len);
    for ("7654321") |byte| buffer.appendAssumeCapacity(byte);
    try testing.expectEqualSlices(u8, "7654321", buffer.constSlice());
    var empty: ArrayBuffer(u8, 0) = .empty;
    try empty.appendSlice("");
    try testing.expectError(error.NoSpaceLeft, empty.append('x'));
    try testing.expectError(error.NoSpaceLeft, empty.appendSlice("x"));
}
