const std = @import("std");
const tls = @import("ztls");

// SPEC §3.6: compile and run the pinned, caller-owned ClientHello API.
test "TLS client starts with verified policy and caller owned buffers" {
    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(std.testing.allocator);
    var reassembly: [65536]u8 = @splat(0);
    defer std.crypto.secureZero(u8, &reassembly);
    var output: [16645]u8 = @splat(0);
    defer std.crypto.secureZero(u8, &output);
    var handshake: tls.ClientHandshake = .init(.{
        .keypairs = .initWithP256(.generate(), .generate()),
        .host_name = "one.one.one.one",
        .now_sec = 0,
        .random = .zero,
        .bundle = &bundle,
        .reassembly = &reassembly,
    });
    defer handshake.deinit();
    const hello = try handshake.start(&output);
    try std.testing.expectEqual(@as(u8, 22), hello[0]);
    try std.testing.expect(std.mem.indexOf(u8, hello, "one.one.one.one") != null);
    handshake.completeWrite();
}

// RFC 8446 §5.1: incomplete TLS records need more bytes, not a partial record.
test "TLS record assembly retains partial input" {
    var storage: [33290]u8 = @splat(0);
    defer std.crypto.secureZero(u8, &storage);
    var records: tls.RecordBuffer = .init(&storage);
    const partial = [_]u8{ 22, 3, 3, 0, 1 };
    @memcpy(records.writable()[0..partial.len], &partial);
    records.advance(partial.len);
    try std.testing.expectEqual(@as(?[]u8, null), try records.next());
    records.writable()[0] = 42;
    records.advance(1);
    const complete = (try records.next()).?;
    try std.testing.expectEqual(@as(usize, 6), complete.len);
    try std.testing.expectEqual(@as(u8, 42), complete[5]);
}

// RFC 8446 §5.2: ciphertext above 2^14 + 256 bytes must be rejected.
test "TLS oversized record rejects before payload arrives" {
    var storage: [33290]u8 = @splat(0);
    defer std.crypto.secureZero(u8, &storage);
    var records: tls.RecordBuffer = .init(&storage);
    const oversized = [_]u8{ 23, 3, 3, 0x41, 0x01 };
    @memcpy(records.writable()[0..oversized.len], &oversized);
    records.advance(oversized.len);
    try std.testing.expectError(error.RecordTooLarge, records.next());
}

// SPEC §3.6: the system trust scan uses Zig 0.16's Io and real timestamp API.
test "system trust bundle loads public roots" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(allocator);
    try bundle.rescan(allocator, io, std.Io.Timestamp.now(io, .real));
    try std.testing.expect(bundle.map.count() > 0);
}
