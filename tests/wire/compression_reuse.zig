const std = @import("std");
const testing = std.testing;

const wire = @import("wire");

// RFC 1035 §4.1.4 and SPEC §3.9: collisions and failed encodes cannot leak old offsets.
test "compression collisions survive dirty reuse and an encoding failure" {
    var names: [2]wire.Name = undefined;
    try names[0].fromText("collision.example.");
    try names[1].fromText("x7334.example.");
    const bucket = std.hash.Wyhash.hash(0, names[0].wire()) % 16384;
    try testing.expectEqual(bucket, std.hash.Wyhash.hash(0, names[1].wire()) % 16384);
    var encoder: wire.Encoder = undefined;
    var output: [512]u8 = undefined;
    for (0..3) |_| {
        try encoder.init(&output, &.{});
        try testing.expect(!encoder.occupied.isSet(bucket));
        for (0..4) |index| try encoder.question(&names[index % 2], 1, 1);
        var packet: wire.Packet = undefined;
        try packet.parse(try encoder.finish());
        var cursor: usize = 12;
        for (0..4) |index| {
            const question = try packet.readQuestion(&cursor);
            var decoded: wire.Name = undefined;
            try packet.name(&decoded, question.name);
            try testing.expectEqualSlices(u8, names[index % 2].wire(), decoded.wire());
        }
        // The name enters the dictionary before the question's final class field fails.
        const limit = 12 + @as(usize, names[0].length) + 2;
        try encoder.init(output[0..limit], &.{});
        try testing.expectError(error.NoSpace, encoder.question(&names[0], 1, 1));
        try testing.expect(encoder.occupied.isSet(bucket));
        try encoder.init(&output, &.{ .id = 0xbeef });
        try testing.expect(!encoder.occupied.isSet(bucket));
        try encoder.question(&names[1], 28, 1);
        try packet.parse(try encoder.finish());
        var decoded: wire.Name = undefined;
        try packet.name(&decoded, 12);
        try testing.expectEqualSlices(u8, names[1].wire(), decoded.wire());
    }
}
