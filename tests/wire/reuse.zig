const std = @import("std");
const wire = @import("wire");
const fixture = @import("fixture.zig");

// SPEC §§1.10, 3.9: dirty scratch words remain unavailable after a logical reset.
test "scratch bitmaps retain backing words and reject stale bits" {
    inline for (.{ wire.records_max, 16384, 65536 }) |capacity| {
        var bits: wire.names.ScratchSet(capacity) = undefined;
        bits.bits = .initFull();
        const original = bits.bits;
        bits.init();
        for (0..capacity) |index| try std.testing.expect(!bits.isSet(index));
        try std.testing.expectEqualSlices(u64, &original.masks, &bits.bits.masks);
        // Each first write must replace the dirty word, including its neighboring bits.
        for (0..bits.bits.masks.len) |word| {
            const offset = @min(capacity - 1, word * 64 + word % 64);
            bits.set(offset);
            for (word * 64..@min(capacity, word * 64 + 64)) |index| {
                try std.testing.expectEqual(index == offset, bits.isSet(index));
            }
        }
        bits.init();
        for (0..capacity) |index| try std.testing.expect(!bits.isSet(index));
        bits.set(capacity - 1);
        try std.testing.expect(bits.isSet(capacity - 1));
        try std.testing.expect(!bits.isSet(capacity - 2));
        try std.testing.expect(!bits.isSet(0));
    }
}

// RFC 1035 §4.1.4 and RFC 3597 §4: old packet provenance cannot admit a new pointer.
test "packet reuse rejects stale opaque provenance after success and failure" {
    var builder: fixture.Builder = undefined;
    var packet: wire.Packet = undefined;
    for (0..3) |_| {
        builder.init();
        builder.record("\x00", 65400, .answer, "\x01x\x00\x00");
        builder.record("\xc0\x17", 1, .answer, &.{ 127, 0, 0, 1 });
        try packet.parse(try builder.finish());
        // An IN A payload has the same shape but supplies no legal pointer target.
        wire.put(u16, builder.bytes[13..15], 1);
        try std.testing.expectError(error.InvalidPointer, packet.parse(try builder.finish()));
        try std.testing.expectError(error.InvalidPointer, packet.parse(try builder.finish()));
    }
}

// RFC 1035 §4.1.4: a reused compression dictionary refers only to the current output.
test "encoder reset retains dirty offsets without retaining old names" {
    var encoder: wire.Encoder = undefined;
    @memset(&encoder.dictionary, 65535);
    var output: [512]u8 = undefined;
    var packet: wire.Packet = undefined;
    for ([_][]const u8{ "long.old.example.", "x.", "long.old.example.", "y.new.example." }) |text| {
        const before = std.hash.Wyhash.hash(0, std.mem.sliceAsBytes(&encoder.dictionary));
        try encoder.init(&output, &.{});
        const after = std.hash.Wyhash.hash(0, std.mem.sliceAsBytes(&encoder.dictionary));
        try std.testing.expectEqual(before, after);
        var name: wire.Name = undefined;
        try name.fromText(text);
        try encoder.question(&name, 1, 1);
        try encoder.question(&name, 28, 1);
        try packet.parse(try encoder.finish());
        var decoded: wire.Name = undefined;
        try packet.name(&decoded, 12);
        try std.testing.expectEqualSlices(u8, name.wire(), decoded.wire());
        const second = 12 + name.length + 4;
        try std.testing.expectEqualSlices(u8, "\xc0\x0c", output[second..][0..2]);
    }
}

// RFC 3597 §4: a name inspection does not publish new parser provenance.
test "name inspection preserves opaque boundary state" {
    var builder: fixture.Builder = undefined;
    builder.init();
    builder.record("\x00", 65400, .answer, "\x01x\x07example\x00");
    var packet: wire.Packet = undefined;
    try packet.parse(try builder.finish());
    const offset = packet.records[0].data_start;
    try std.testing.expect(!packet.boundaries.isSet(offset));
    var name: wire.Name = undefined;
    try packet.name(&name, offset);
    try std.testing.expectEqualSlices(u8, "\x01x\x07example\x00", name.wire());
    try std.testing.expect(!packet.boundaries.isSet(offset));
}
