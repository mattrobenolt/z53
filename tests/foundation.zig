const std = @import("std");
const testing = std.testing;

const tls = @import("ztls");

// SPEC §3.6: compile and run the pinned, caller-owned ClientHello API.
test "TLS client starts with verified policy and caller owned buffers" {
    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(testing.allocator);
    var reassembly: [65536]u8 = @splat(0);
    defer std.crypto.secureZero(u8, &reassembly);
    var output: [16645]u8 = @splat(0);
    defer std.crypto.secureZero(u8, &output);
    var x25519: tls.x25519.KeyPair = .generate();
    defer x25519.secureZero();
    var p256: tls.p256.KeyPair = try .generate();
    defer p256.secureZero();
    const hybrid_groups = [_]tls.kex.NamedGroup{.x25519_mlkem768};
    var config: tls.ClientHandshake.Config = .{
        .keypairs = .initWithP256(x25519, p256),
        .host_name = "one.one.one.one",
        .now_sec = 0,
        .random = .zero,
        .bundle = &bundle,
        .reassembly = &reassembly,
        .hybrid = .{
            .supported_groups = &hybrid_groups,
            .initial_key_share = .x25519_mlkem768,
        },
    };
    defer config.keypairs.secureZero();
    try config.validate();
    var handshake: tls.ClientHandshake = .init(config);
    defer handshake.deinit();
    const hello = try handshake.start(&output);
    try testing.expectEqual(@as(u8, 22), hello[0]);
    try testing.expect(std.mem.indexOf(u8, hello, "one.one.one.one") != null);
    const parsed = try tls.client_hello.parse(hello[5..]);
    try testing.expect(parsed.public_key != null);
    try testing.expect(parsed.public_key_p256 != null);
    try testing.expectEqual(@as(usize, 1), parsed.hybrid_key_shares.len);
    try testing.expectEqual(
        tls.kex.NamedGroup.x25519_mlkem768,
        parsed.hybrid_key_shares.constSlice()[0].group,
    );
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
    try testing.expectEqual(@as(?[]u8, null), try records.next());
    records.writable()[0] = 42;
    records.advance(1);
    const complete = (try records.next()).?;
    try testing.expectEqual(@as(usize, 6), complete.len);
    try testing.expectEqual(@as(u8, 42), complete[5]);
}

// RFC 8446 §5.2: ciphertext above 2^14 + 256 bytes must be rejected.
test "TLS oversized record rejects before payload arrives" {
    var storage: [33290]u8 = @splat(0);
    defer std.crypto.secureZero(u8, &storage);
    var records: tls.RecordBuffer = .init(&storage);
    const oversized = [_]u8{ 23, 3, 3, 0x41, 0x01 };
    @memcpy(records.writable()[0..oversized.len], &oversized);
    records.advance(oversized.len);
    try testing.expectError(error.RecordTooLarge, records.next());
}

// SPEC §3.6: the system trust scan uses Zig 0.16's Io and real timestamp API.
test "system trust bundle loads public roots" {
    const allocator = testing.allocator;
    const io = testing.io;
    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(allocator);
    try bundle.rescan(allocator, io, std.Io.Timestamp.now(io, .real));
    try testing.expect(bundle.map.count() > 0);
}
