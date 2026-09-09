//! A slot cannot rearm until both the target and its cancellation acknowledge completion.
const builtin = @import("builtin");
const runtime = @import("../runtime.zig");
const std = @import("std");
const assert = std.debug.assert;

pub const Completion = enum { more, terminal, cancellation };

pub const Ownership = struct {
    generation: u31 = 0,
    state: enum { idle, active, cancelling, target_done, cancel_done } = .idle,

    pub fn arm(self: *Ownership, index: u32) error{GenerationExhausted}!u64 {
        assert(self.state == .idle);
        if (self.generation == std.math.maxInt(u31)) return error.GenerationExhausted;
        self.generation += 1;
        self.state = .active;
        return self.token(index);
    }

    pub fn token(self: *const Ownership, index: u32) u64 {
        return (@as(u64, self.generation) << 32) | index;
    }

    pub fn cancel(self: *Ownership) void {
        assert(self.state == .active);
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

comptime {
    if (builtin.is_test) _ = RuntimeUnitTests;
}

const RuntimeUnitTests = struct {
    const testing = std.testing;
    const linux = std.os.linux;
    const wire = runtime.pipeline.wire;

    // SPEC §1: cancellation and target completion jointly release ownership, in either order.
    test "completion generations and cancellation barriers" {
        var owner: runtime.proctor.Ownership = .{};
        const first = try owner.arm(4);
        try owner.complete(first, .more);
        owner.cancel();
        try owner.complete(first, .terminal);
        try testing.expectEqual(.target_done, owner.state);
        try owner.complete(first, .cancellation);
        const second = try owner.arm(4);
        try testing.expectError(error.InvalidCompletion, owner.complete(first, .terminal));
        owner.cancel();
        try owner.complete(second, .cancellation);
        try testing.expectEqual(.cancel_done, owner.state);
        try owner.complete(second, .more);
        try owner.complete(second, .terminal);
        try testing.expectEqual(.idle, owner.state);
        owner.generation = std.math.maxInt(u31);
        try testing.expectError(error.GenerationExhausted, owner.arm(4));
    }

    // SPEC §1: one-shot readiness consumption or synchronous deletion permits reuse, not replay.
    test "readiness ownership releases exactly once and rejects stale reuse" {
        var owner: runtime.proctor.Ownership = .{};
        const ready = try owner.arm(7);
        try owner.complete(ready, .terminal);
        try testing.expectEqual(.idle, owner.state);
        try testing.expectError(error.InvalidCompletion, owner.complete(ready, .terminal));
        const replacement = try owner.arm(7);
        try testing.expectError(error.InvalidCompletion, owner.complete(ready, .terminal));
        try testing.expectEqual(.active, owner.state);
        // The kqueue backend completes terminal ownership only after EV_DELETE succeeds.
        try owner.complete(replacement, .terminal);
        try testing.expectEqual(.idle, owner.state);
    }
};
