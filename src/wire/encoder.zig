const builtin = @import("builtin");
const fixture = @import("../testing/wire.zig");
const std = @import("std");
const Wyhash = std.hash.Wyhash;
const assert = std.debug.assert;

const wire = @import("../wire.zig");
const names = wire.names;

/// Output and input must not overlap. Any error invalidates this encoder.
/// Every compression entry refers to the current output, never the input.
pub const Encoder = struct {
    output: []u8,
    cursor: usize,
    header: wire.Header,
    dictionary: [names.compression_targets_max]u16,
    occupied: names.ScratchSet(names.compression_targets_max),
    boundaries: names.Boundaries,
    section: wire.Section,

    pub fn init(self: *Encoder, output: []u8, header: *const wire.Header) wire.Error!void {
        if (output.len < wire.header_bytes) return error.NoSpace;
        self.output = output[0..@min(output.len, wire.message_bytes_max)];
        self.cursor = wire.header_bytes;
        self.header = header.*;
        self.header.counts = @splat(0);
        self.occupied.init();
        self.boundaries.init();
        self.section = .question;
    }

    pub fn finish(self: *Encoder) wire.Error![]const u8 {
        try self.header.encode(self.output);
        return self.output[0..self.cursor];
    }

    pub fn bytes(self: *Encoder, value: []const u8) wire.Error!void {
        if (value.len > self.output.len - self.cursor) return error.NoSpace;
        @memcpy(self.output[self.cursor..][0..value.len], value);
        self.cursor += value.len;
    }

    pub fn number(self: *Encoder, comptime T: type, value: T) wire.Error!void {
        var buffer: [@sizeOf(T)]u8 = undefined;
        wire.put(T, &buffer, value);
        try self.bytes(&buffer);
    }

    pub fn name(
        self: *Encoder,
        value: *const wire.Name,
        compression: names.Compression,
    ) wire.Error!void {
        try value.validate();
        const start = self.cursor;
        var index: usize = 0;
        while (index + 1 < value.length) {
            if (compression == .allowed) {
                if (self.lookup(value.wire()[index..])) |offset| {
                    try self.number(u16, names.pointer_tag | offset);
                    break;
                }
            }
            const length: usize = value.bytes[index];
            try self.bytes(value.wire()[index..][0 .. length + 1]);
            index += length + 1;
        }
        if (index + 1 == value.length) try self.bytes(&.{0});
        var suffix: usize = 0;
        while (suffix <= index) {
            const offset = start + suffix;
            if (offset >= names.compression_targets_max) break;
            self.boundaries.set(offset);
            if (suffix + 1 == value.length) break;
            self.insert(value.wire()[suffix..], @intCast(offset));
            suffix += @as(usize, value.bytes[suffix]) + 1;
        }
    }

    fn lookup(self: *Encoder, suffix: []const u8) ?u16 {
        const hash = Wyhash.hash(0, suffix);
        for (0..self.dictionary.len) |probe| {
            const slot = (hash +% probe) % self.dictionary.len;
            if (!self.occupied.isSet(slot)) return null;
            const offset = self.dictionary[slot];
            var expanded: wire.Name = undefined;
            _ = names.decode(
                &expanded,
                self.output,
                offset,
                self.cursor,
                &self.boundaries,
                .allowed,
            ) catch continue;
            if (std.mem.eql(u8, expanded.wire(), suffix)) return offset;
        }
        return null;
    }

    fn insert(self: *Encoder, suffix: []const u8, offset: u16) void {
        const hash = Wyhash.hash(0, suffix);
        for (0..self.dictionary.len) |probe| {
            const slot = (hash +% probe) % self.dictionary.len;
            if (self.occupied.isSet(slot)) continue;
            self.dictionary[slot] = offset;
            self.occupied.set(slot);
            return;
        }
        // Saturation reduces compression only; offsets never alias new data.
    }

    pub fn question(
        self: *Encoder,
        value: *const wire.Name,
        kind: wire.RecordType,
        class: u16,
    ) wire.Error!void {
        if (self.section != .question) return error.InvalidOrder;
        try self.name(value, .allowed);
        try self.number(u16, @intFromEnum(kind));
        try self.number(u16, class);
        self.header.counts[0] += 1;
    }

    /// Returns the RDLENGTH offset. Call endRecord after writing its RDATA.
    pub fn beginRecord(
        self: *Encoder,
        owner: *const wire.Name,
        value: *const wire.Record,
    ) wire.Error!usize {
        if (value.section == .question) return error.InvalidOrder;
        if (@intFromEnum(value.section) < @intFromEnum(self.section)) return error.InvalidOrder;
        self.section = value.section;
        try self.name(owner, .allowed);
        try self.number(u16, @intFromEnum(value.kind));
        try self.number(u16, value.class);
        try self.number(u32, value.ttl_s);
        const offset = self.cursor;
        try self.number(u16, 0);
        self.header.counts[@intFromEnum(value.section)] += 1;
        return offset;
    }

    pub fn endRecord(self: *Encoder, length_offset: usize) void {
        assert(length_offset + 2 <= self.cursor);
        const length: u16 = @intCast(self.cursor - length_offset - 2);
        wire.put(u16, self.output[length_offset..][0..2], length);
    }

    pub fn record(self: *Encoder, packet: *wire.Packet, value: *const wire.Record) wire.Error!void {
        var owner: wire.Name = undefined;
        try packet.name(&owner, value.owner);
        const length_offset = try self.beginRecord(&owner, value);
        var parts: wire.rdata.Parts = undefined;
        try wire.rdata.parse(&parts, packet, value);
        for (parts.items.constSlice()) |part| {
            switch (part) {
                .bytes => |range| try self.bytes(packet.bytes[range.start..range.end]),
                .name => |reference| {
                    var expanded: wire.Name = undefined;
                    try packet.name(&expanded, reference.offset);
                    try self.name(&expanded, reference.compression);
                },
            }
        }
        self.endRecord(length_offset);
    }
};

comptime {
    if (builtin.is_test) _ = WireTestsReuse;
}

const WireTestsReuse = struct {
    const testing = std.testing;

    // SPEC §§1.10, 3.9: dirty scratch words remain unavailable after a logical reset.
    test "scratch bitmaps retain backing words and reject stale bits" {
        inline for (.{ wire.records_max, 16384, 65536 }) |capacity| {
            var bits: wire.names.ScratchSet(capacity) = undefined;
            bits.bits = .initFull();
            const original = bits.bits;
            bits.init();
            for (0..capacity) |index| try testing.expect(!bits.isSet(index));
            try testing.expectEqualSlices(u64, &original.masks, &bits.bits.masks);
            // Each first write must replace the dirty word, including its neighboring bits.
            for (0..bits.bits.masks.len) |word| {
                const offset = @min(capacity - 1, word * 64 + word % 64);
                bits.set(offset);
                for (word * 64..@min(capacity, word * 64 + 64)) |index| {
                    try testing.expectEqual(index == offset, bits.isSet(index));
                }
            }
            bits.init();
            for (0..capacity) |index| try testing.expect(!bits.isSet(index));
            bits.set(capacity - 1);
            try testing.expect(bits.isSet(capacity - 1));
            try testing.expect(!bits.isSet(capacity - 2));
            try testing.expect(!bits.isSet(0));
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
            try testing.expectError(error.InvalidPointer, packet.parse(try builder.finish()));
            try testing.expectError(error.InvalidPointer, packet.parse(try builder.finish()));
        }
    }

    // RFC 1035 §4.1.4: a reused compression dictionary refers only to the current output.
    test "encoder reset retains dirty offsets without retaining old names" {
        var encoder: wire.Encoder = undefined;
        @memset(&encoder.dictionary, 65535);
        var output: [512]u8 = undefined;
        var packet: wire.Packet = undefined;
        for ([_][]const u8{
            "long.old.example.",
            "x.",
            "long.old.example.",
            "y.new.example.",
        }) |text| {
            const before = std.hash.Wyhash.hash(0, std.mem.sliceAsBytes(&encoder.dictionary));
            try encoder.init(&output, &.{});
            const after = std.hash.Wyhash.hash(0, std.mem.sliceAsBytes(&encoder.dictionary));
            try testing.expectEqual(before, after);
            var name: wire.Name = undefined;
            try name.fromText(text);
            try encoder.question(&name, .a, 1);
            try encoder.question(&name, .aaaa, 1);
            try packet.parse(try encoder.finish());
            var decoded: wire.Name = undefined;
            try packet.name(&decoded, 12);
            try testing.expectEqualSlices(u8, name.wire(), decoded.wire());
            const second = 12 + name.length + 4;
            try testing.expectEqualSlices(u8, "\xc0\x0c", output[second..][0..2]);
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
        try testing.expect(!packet.boundaries.isSet(offset));
        var name: wire.Name = undefined;
        try packet.name(&name, offset);
        try testing.expectEqualSlices(u8, "\x01x\x07example\x00", name.wire());
        try testing.expect(!packet.boundaries.isSet(offset));
    }
};

comptime {
    if (builtin.is_test) _ = WireTestsCompressionReuse;
}

const WireTestsCompressionReuse = struct {
    const testing = std.testing;

    // RFC 1035 §4.1.4 and SPEC §3.9: collisions and failed encodes cannot leak old offsets.
    test "compression collisions survive dirty reuse and an encoding failure" {
        var query_names: [2]wire.Name = undefined;
        try query_names[0].fromText("collision.example.");
        try query_names[1].fromText("x7334.example.");
        const bucket = std.hash.Wyhash.hash(0, query_names[0].wire()) % 16384;
        try testing.expectEqual(bucket, std.hash.Wyhash.hash(0, query_names[1].wire()) % 16384);
        var encoder: wire.Encoder = undefined;
        var output: [512]u8 = undefined;
        for (0..3) |_| {
            try encoder.init(&output, &.{});
            try testing.expect(!encoder.occupied.isSet(bucket));
            for (0..4) |index| try encoder.question(&query_names[index % 2], .a, 1);
            var packet: wire.Packet = undefined;
            try packet.parse(try encoder.finish());
            var cursor: usize = 12;
            for (0..4) |index| {
                const question = try packet.readQuestion(&cursor);
                var decoded: wire.Name = undefined;
                try packet.name(&decoded, question.name);
                try testing.expectEqualSlices(u8, query_names[index % 2].wire(), decoded.wire());
            }
            // The name enters the dictionary before the question's final class field fails.
            const limit = 12 + @as(usize, query_names[0].length) + 2;
            try encoder.init(output[0..limit], &.{});
            try testing.expectError(error.NoSpace, encoder.question(&query_names[0], .a, 1));
            try testing.expect(encoder.occupied.isSet(bucket));
            try encoder.init(&output, &.{ .id = 0xbeef });
            try testing.expect(!encoder.occupied.isSet(bucket));
            try encoder.question(&query_names[1], .aaaa, 1);
            try packet.parse(try encoder.finish());
            var decoded: wire.Name = undefined;
            try packet.name(&decoded, 12);
            try testing.expectEqualSlices(u8, query_names[1].wire(), decoded.wire());
        }
    }
};
