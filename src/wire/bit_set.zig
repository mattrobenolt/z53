const std = @import("std");

/// Only the small word-validity map resets. Dirty backing words stay unread until their first set.
pub fn ScratchSet(comptime capacity: usize) type {
    const Bits = std.bit_set.ArrayBitSet(u64, capacity);
    const words = std.math.divCeil(usize, capacity, 64) catch unreachable;
    return struct {
        bits: Bits,
        initialized: std.StaticBitSet(words),
        const Self = @This();

        pub fn init(self: *Self) void {
            self.initialized = .initEmpty();
        }

        pub fn isSet(self: *const Self, index: usize) bool {
            std.debug.assert(index < capacity);
            if (!self.initialized.isSet(index / 64)) return false;
            return self.bits.isSet(index);
        }

        pub fn set(self: *Self, index: usize) void {
            std.debug.assert(index < capacity);
            const word = index / 64;
            if (!self.initialized.isSet(word)) {
                self.bits.masks[word] = 0;
                self.initialized.set(word);
            }
            self.bits.set(index);
        }
    };
}
