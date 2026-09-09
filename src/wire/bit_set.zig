const std = @import("std");
const assert = std.debug.assert;

/// Only the small word-validity map resets. Dirty backing words stay unread until their first set.
pub fn ScratchSet(comptime capacity: usize) type {
    const Bits = std.bit_set.ArrayBitSet(u64, capacity);
    const words = std.math.divCeil(usize, capacity, 64) catch unreachable;
    return struct {
        // Backing words can be stale or undefined. Only isSet and set expose logical membership.
        bits: Bits,
        initialized: std.bit_set.ArrayBitSet(u64, words),
        const Self = @This();

        pub fn init(self: *Self) void {
            self.initialized = .initEmpty();
        }

        pub fn isSet(self: *const Self, index: usize) bool {
            assert(index < capacity);
            if (!contains(&self.initialized.masks, index / 64)) return false;
            return contains(&self.bits.masks, index);
        }

        pub fn set(self: *Self, index: usize) void {
            assert(index < capacity);
            const word = index / 64;
            if (!contains(&self.initialized.masks, word)) {
                self.bits.masks[word] = 0;
                self.initialized.set(word);
            }
            self.bits.set(index);
        }

        fn contains(masks: []const u64, index: usize) bool {
            // ArrayBitSet.isSet takes its entire backing array by value.
            const word: std.bit_set.IntegerBitSet(64) = .{ .mask = masks[index / 64] };
            return word.isSet(index % 64);
        }
    };
}
