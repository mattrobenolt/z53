//! A slot cannot rearm until both the target and its cancellation acknowledge completion.
const std = @import("std");

pub const Completion = enum { more, terminal, cancellation };
pub const Ownership = struct {
    generation: u31 = 0,
    state: enum { idle, active, cancelling, target_done, cancel_done } = .idle,

    pub fn arm(self: *Ownership, index: u32) error{GenerationExhausted}!u64 {
        std.debug.assert(self.state == .idle);
        if (self.generation == std.math.maxInt(u31)) return error.GenerationExhausted;
        self.generation += 1;
        self.state = .active;
        return self.token(index);
    }

    pub fn token(self: *const Ownership, index: u32) u64 {
        return (@as(u64, self.generation) << 32) | index;
    }

    pub fn cancel(self: *Ownership) void {
        std.debug.assert(self.state == .active);
        self.state = .cancelling;
    }

    pub fn complete(
        self: *Ownership,
        token_value: u64,
        kind: Completion,
    ) error{InvalidCompletion}!void {
        const generation: u31 = @truncate(token_value >> 32);
        if (generation != self.generation) return error.InvalidCompletion;
        switch (kind) {
            .more => switch (self.state) {
                .active, .cancelling, .cancel_done => {},
                else => return error.InvalidCompletion,
            },
            .terminal => self.state = switch (self.state) {
                .active, .cancel_done => .idle,
                .cancelling => .target_done,
                else => return error.InvalidCompletion,
            },
            .cancellation => self.state = switch (self.state) {
                .cancelling => .cancel_done,
                .target_done => .idle,
                else => return error.InvalidCompletion,
            },
        }
    }
};
