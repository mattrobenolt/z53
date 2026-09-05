const std = @import("std");
const wire = @import("wire");

pub fn equivalent(
    source: *wire.Packet,
    left: *const wire.Record,
    target: *wire.Packet,
    right: *const wire.Record,
) !void {
    try std.testing.expectEqual(left.kind, right.kind);
    try std.testing.expectEqual(left.class, right.class);
    try std.testing.expectEqual(left.ttl_s, right.ttl_s);
    try std.testing.expectEqual(left.section, right.section);
    var source_name: wire.Name = undefined;
    var target_name: wire.Name = undefined;
    try source.name(&source_name, left.owner);
    try target.name(&target_name, right.owner);
    try std.testing.expectEqualSlices(u8, source_name.wire(), target_name.wire());
    var source_parts: wire.rdata.Parts = undefined;
    var target_parts: wire.rdata.Parts = undefined;
    try wire.rdata.parse(&source_parts, source, left);
    try wire.rdata.parse(&target_parts, target, right);
    try std.testing.expectEqual(source_parts.count, target_parts.count);
    const first_parts = source_parts.items[0..source_parts.count];
    const second_parts = target_parts.items[0..target_parts.count];
    for (first_parts, second_parts) |first, second| {
        switch (first) {
            .bytes => |range| try std.testing.expectEqualSlices(
                u8,
                source.bytes[range.start..range.end],
                target.bytes[second.bytes.start..second.bytes.end],
            ),
            .name => |reference| {
                try source.name(&source_name, reference.offset);
                try target.name(&target_name, second.name.offset);
                try std.testing.expectEqualSlices(u8, source_name.wire(), target_name.wire());
                if (reference.compression == .forbidden) {
                    try std.testing.expect(target.bytes[second.name.offset] < 64);
                }
            },
        }
    }
}
