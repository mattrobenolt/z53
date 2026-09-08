const std = @import("std");
const ArrayBuffer = @import("wire").ArrayBuffer;

// SPEC §§1.10, 1.11: a bounded buffer retains dirty storage across logical resets.
test "array buffer clear retains backing storage and exposes only live elements" {
    var buffer: ArrayBuffer(u8, 7) = .empty;
    @memset(&buffer.buffer, 0xa5);
    try buffer.appendSlice("old");
    const retained = buffer.buffer;
    buffer.clear();
    try std.testing.expectEqual(0, buffer.len);
    try std.testing.expectEqual(7, buffer.remainingCapacity());
    try std.testing.expectEqualSlices(u8, &retained, &buffer.buffer);
    try std.testing.expectEqual(0, buffer.constSlice().len);
    try buffer.append('x');
    try std.testing.expectEqualSlices(u8, "x", buffer.constSlice());
    buffer.slice()[0] = 'y';
    try std.testing.expectEqualSlices(u8, "y", buffer.constSlice());
    try std.testing.expectEqual(6, buffer.unusedCapacitySlice().len);
}

// SPEC §3.9: capacity checks precede narrow index conversion and preserve existing elements.
test "array buffer overflow preserves contents at non power of two capacity" {
    var buffer: ArrayBuffer(u8, 7) = .empty;
    try buffer.appendSlice("1234567");
    try std.testing.expectError(error.NoSpaceLeft, buffer.append('x'));
    try std.testing.expectError(error.NoSpaceLeft, buffer.appendSlice("x"));
    try std.testing.expectEqualSlices(u8, "1234567", buffer.constSlice());
    buffer.clear();
    const oversized: [256]u8 = @splat(0);
    try std.testing.expectError(error.NoSpaceLeft, buffer.appendSlice(&oversized));
    try std.testing.expectEqual(0, buffer.len);
    for ("7654321") |byte| buffer.appendAssumeCapacity(byte);
    try std.testing.expectEqualSlices(u8, "7654321", buffer.constSlice());
    var empty: ArrayBuffer(u8, 0) = .empty;
    try empty.appendSlice("");
    try std.testing.expectError(error.NoSpaceLeft, empty.append('x'));
    try std.testing.expectError(error.NoSpaceLeft, empty.appendSlice("x"));
}
