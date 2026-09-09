const builtin = @import("builtin");
const wire = @import("../wire.zig");
const fixture = @import("../testing/wire.zig");
const equivalent_module = @import("../testing/equivalent.zig");
const equivalent = equivalent_module.equivalent;
const std = @import("std");

pub const ScratchSet = @import("bit_set.zig").ScratchSet;

pub const Error = error{
    Truncated,
    LabelTooLong,
    NameTooLong,
    InvalidPointer,
    CompressionForbidden,
    InvalidName,
};

pub const name_bytes_max = 255;
pub const label_bytes_max = 63;
pub const compression_targets_max = 1 << 14;
pub const name_steps_max = compression_targets_max + (name_bytes_max + 1) / 2;
pub const pointer_tag: u16 = 0xc000;
pub const label_kind_mask: u8 = 0xc0;
pub const label_value_mask: u8 = 0x3f;

pub const Compression = enum { allowed, forbidden };

pub const Boundaries = struct {
    labels: ScratchSet(compression_targets_max),
    opaque_bytes: ScratchSet(65536),

    pub fn init(self: *Boundaries) void {
        self.labels.init();
        self.opaque_bytes.init();
    }

    pub fn isSet(self: *const Boundaries, index: usize) bool {
        return self.labels.isSet(index);
    }

    pub fn set(self: *Boundaries, index: usize) void {
        self.labels.set(index);
    }
};

/// Length-prefixed labels preserve dots, zero bytes, and case without ambiguity.
pub const Name = struct {
    bytes: [name_bytes_max]u8 = undefined,
    length: u8 = 0,

    pub fn wire(self: *const Name) []const u8 {
        return self.bytes[0..self.length];
    }

    pub fn fromText(self: *Name, text: []const u8) Error!void {
        self.length = 0;
        if (std.mem.eql(u8, text, ".")) {
            try self.append(&.{0});
            return;
        }
        if (text.len == 0) return error.InvalidName;
        if (text.len > name_bytes_max - 1) return error.NameTooLong;
        const end = text.len - @intFromBool(text[text.len - 1] == '.');
        var labels = std.mem.splitScalar(u8, text[0..end], '.');
        while (labels.next()) |label| {
            if (label.len == 0) return error.InvalidName;
            if (label.len > label_bytes_max) return error.LabelTooLong;
            try self.append(&.{@intCast(label.len)});
            try self.append(label);
        }
        try self.append(&.{0});
    }

    pub fn append(self: *Name, bytes: []const u8) Error!void {
        const end = @as(usize, self.length) + bytes.len;
        if (end > name_bytes_max) return error.NameTooLong;
        @memcpy(self.bytes[self.length..end], bytes);
        self.length = @intCast(end);
    }

    pub fn validate(self: *const Name) Error!void {
        var index: usize = 0;
        while (index < self.length) {
            const length = self.bytes[index];
            if (length > label_bytes_max) return error.LabelTooLong;
            index += 1;
            if (length == 0) {
                if (index != self.length) return error.InvalidName;
                return;
            }
            if (index + @as(usize, length) >= self.length) return error.InvalidName;
            index += length;
        }
        return error.InvalidName;
    }

    pub fn eql(self: *const Name, other: *const Name) bool {
        // DNS equality folds ASCII only; label framing remains significant.
        return std.ascii.eqlIgnoreCase(self.wire(), other.wire());
    }
};

/// Boundaries belong to one immutable packet and are built in wire order.
/// A pointer references a decoded label or a bounded name in prior unknown RDATA.
pub fn decode(
    target: *Name,
    packet: []const u8,
    start: usize,
    end: usize,
    boundaries: *Boundaries,
    compression: Compression,
) Error!usize {
    return decodeWith(.record, target, packet, start, end, boundaries, compression);
}

/// Reads a name against boundaries already recorded by decode, leaving them unchanged.
pub fn read(
    target: *Name,
    packet: []const u8,
    start: usize,
    end: usize,
    boundaries: *const Boundaries,
    compression: Compression,
) Error!usize {
    return decodeWith(.inspect, target, packet, start, end, boundaries, compression);
}

const Access = enum { record, inspect };

fn BoundaryPointer(comptime access: Access) type {
    return if (access == .record) *Boundaries else *const Boundaries;
}

fn decodeWith(
    comptime access: Access,
    target: *Name,
    packet: []const u8,
    start: usize,
    end: usize,
    boundaries: BoundaryPointer(access),
    compression: Compression,
) Error!usize {
    target.length = 0;
    if (end > packet.len) return error.Truncated;
    if (packet.len > 65535) return error.InvalidName;
    var cursor = start;
    var ceiling = end;
    var consumed: ?usize = null;
    var steps: u16 = 0;
    while (steps < name_steps_max) : (steps += 1) {
        if (cursor >= ceiling) return error.Truncated;
        const length = packet[cursor];
        if (length & label_kind_mask == label_kind_mask) {
            if (compression == .forbidden) return error.CompressionForbidden;
            if (cursor + 2 > ceiling) return error.Truncated;
            const pointer = (@as(usize, length & label_value_mask) << 8) | packet[cursor + 1];
            if (pointer >= cursor) return error.InvalidPointer;
            if (!boundaries.isSet(pointer)) {
                try decodeOpaque(access, target, packet, pointer, cursor, boundaries);
                mark(access, boundaries, cursor);
                return consumed orelse cursor + 2;
            }
            if (consumed == null) consumed = cursor + 2;
            mark(access, boundaries, cursor);
            ceiling = cursor;
            cursor = pointer;
            continue;
        }
        if (length > label_bytes_max) return error.LabelTooLong;
        const next = cursor + 1 + @as(usize, length);
        if (next > ceiling) return error.Truncated;
        mark(access, boundaries, cursor);
        try target.append(packet[cursor..next]);
        cursor = next;
        if (length == 0) return consumed orelse cursor;
    }
    return error.InvalidPointer;
}

fn mark(comptime access: Access, boundaries: BoundaryPointer(access), offset: usize) void {
    if (access == .record) {
        if (offset < compression_targets_max) boundaries.set(offset);
    }
}

fn decodeOpaque(
    comptime access: Access,
    target: *Name,
    packet: []const u8,
    start: usize,
    ceiling: usize,
    boundaries: BoundaryPointer(access),
) Error!void {
    var suffix: Name = .{ .length = 0 };
    var cursor = start;
    while (cursor < ceiling) {
        if (!boundaries.opaque_bytes.isSet(cursor)) return error.InvalidPointer;
        const length = packet[cursor];
        if (length & label_kind_mask == label_kind_mask) return error.InvalidPointer;
        if (length > label_bytes_max) return error.LabelTooLong;
        const next = cursor + @as(usize, length) + 1;
        if (next > ceiling) return error.InvalidPointer;
        for (cursor..next) |offset| {
            if (!boundaries.opaque_bytes.isSet(offset)) return error.InvalidPointer;
        }
        try suffix.append(packet[cursor..next]);
        cursor = next;
        if (length != 0) continue;
        try target.append(suffix.wire());
        // Publish boundaries only after the entire fallback and prefixed name pass.
        if (access == .record) {
            var offset = start;
            while (offset < cursor) {
                mark(access, boundaries, offset);
                offset += @as(usize, packet[offset]) + 1;
            }
        }
        return;
    }
    return error.InvalidPointer;
}

comptime {
    if (builtin.is_test) _ = WireTestsNames;
}

const WireTestsNames = struct {
    const testing = std.testing;

    // RFC 1035 §2.3.4 and SPEC §9.1: 63-byte labels and 255-byte names are inclusive.
    test "name exact bounds and hostile label encodings" {
        var name: wire.Name = undefined;
        try fixture.maxName(&name);
        try name.validate();
        try testing.expectEqual(255, name.length);
        var builder: fixture.Builder = undefined;
        builder.init();
        builder.question(name.wire(), 1, 1);
        var packet: wire.Packet = undefined;
        try packet.parse(try builder.finish());
        for ([_]u8{ 64, 128, 191 }) |invalid| {
            builder.bytes[12] = invalid;
            try testing.expectError(error.LabelTooLong, packet.parse(try builder.finish()));
        }
        try testing.expectError(error.NameTooLong, name.append(&.{0}));
        var long: [256]u8 = @splat('a');
        for ([_]usize{ 0, 64, 128 }) |offset| long[offset] = 63;
        long[192] = 62;
        long[255] = 0;
        builder.init();
        builder.question(&long, 1, 1);
        try testing.expectError(error.NameTooLong, packet.parse(try builder.finish()));
        try testing.expectError(error.LabelTooLong, name.fromText("a" ** 64));
        try testing.expectError(error.InvalidName, name.fromText("a..b"));
        try testing.expectError(error.InvalidName, name.fromText(""));
    }

    // RFC 1035 §4.1.4: suffix and pointer chains resolve only prior label boundaries.
    test "compressed names decode suffixes and pointer chains" {
        var builder: fixture.Builder = undefined;
        builder.init();
        builder.question("\x03www\x07example\x00", 1, 3);
        const second: u16 = @intCast(builder.cursor);
        builder.question("\x03api\xc0\x10", 28, 1);
        builder.number(u16, 0xc000 | second);
        builder.number(u16, 15);
        builder.number(u16, 1);
        builder.header.counts[0] += 1;
        var packet: wire.Packet = undefined;
        try packet.parse(try builder.finish());
        var name: wire.Name = undefined;
        try packet.name(&name, @intCast(second + 10));
        try testing.expectEqualSlices(u8, "\x03api\x07example\x00", name.wire());
    }

    // RFC 1035 §4.1.4 and SPEC §3.9: corrupt pointers never become names.
    test "pointer targets reject header interior forward self and cycles" {
        var builder: fixture.Builder = undefined;
        builder.init();
        builder.question("\x03www\x00", 1, 1);
        const offset = builder.cursor;
        builder.question("\xc0\x0c", 1, 1);
        var packet: wire.Packet = undefined;
        for ([_]u16{ 0, 13, @intCast(offset), @intCast(offset + 2), 0x3fff }) |pointer| {
            wire.put(u16, builder.bytes[offset..][0..2], 0xc000 | pointer);
            try testing.expectError(error.InvalidPointer, packet.parse(try builder.finish()));
        }
        builder.init();
        builder.question("\x01a\xc0\x0c", 1, 1);
        try testing.expectError(error.Truncated, packet.parse(try builder.finish()));
    }

    // RFC 1035 §2.3.3: names contain arbitrary octets, not dot-delimited text.
    test "binary name representation does not alias label separators" {
        var source: wire.Name = .{ .length = 0 };
        try source.append("\x03a.b\x00");
        var target: wire.Name = undefined;
        try target.fromText("a.b.");
        try testing.expect(!source.eql(&target));
        try source.fromText("WWW.Example.");
        try target.fromText("www.example");
        try testing.expect(source.eql(&target));
        try source.fromText(".");
        try testing.expectEqualSlices(u8, &.{0}, source.wire());
    }
};

comptime {
    if (builtin.is_test) _ = WireTestsOpaque;
}

const WireTestsOpaque = struct {
    const testing = std.testing;

    // RFC 3597 §4 and RFC 9460 §2.2: later owners may reference uncompressed SVCB targets.
    test "SVCB target supplies a later compressed owner without changing opaque RDATA" {
        var builder: fixture.Builder = undefined;
        builder.init();
        builder.question("\x01x\x00", 64, 1);
        builder.record("\xc0\x0c", 64, .answer, "\x00\x01\x06target\x07example\x00");
        builder.record("\xc0\x21", 1, .additional, &.{ 127, 0, 0, 1 });
        const bytes = try builder.finish();
        try testing.expectEqual(65, bytes.len);
        var packet: wire.Packet = undefined;
        try packet.parse(bytes);
        try checkRelocation(&packet, "\x06target\x07example\x00", &.{});
    }

    // RFC 3597 §§3–4: structural provenance works for arbitrary unknown type/class layouts.
    test "unknown RDATA owner is encoded afresh even when moved before its source" {
        var builder: fixture.Builder = undefined;
        for ([_]u16{ 65400, 1 }) |kind| {
            builder.init();
            builder.record("\x00", kind, .answer, "\xff\x02\x01x\x07example\x00\xc0\xff");
            wire.put(u16, builder.bytes[15..17], 65200);
            builder.record("\xc0\x19", 1, .answer, &.{ 127, 0, 0, 1 });
            var packet: wire.Packet = undefined;
            try packet.parse(try builder.finish());
            try checkRelocation(&packet, "\x01x\x07example\x00", &.{ 1, 0 });
        }
    }

    fn checkRelocation(packet: *wire.Packet, expected: []const u8, order: []const u16) !void {
        var name: wire.Name = undefined;
        try packet.name(&name, packet.records[1].owner);
        try testing.expectEqualSlices(u8, expected, name.wire());
        var replacement: wire.Name = undefined;
        try replacement.fromText("changed.example.");
        var workspace: wire.rewrite.Workspace = undefined;
        var output: [65535]u8 = undefined;
        const result = try workspace.rewrite(packet, &output, &.{
            .order = order,
            .question = .{ .name = &replacement, .kind = .svcb, .class = 1 },
        });
        var decoded: wire.Packet = undefined;
        try decoded.parse(result);
        try testing.expectEqual(packet.record_count, decoded.record_count);
        for (0..packet.record_count) |position| {
            const source = if (order.len == 0) position else order[position];
            try equivalent(packet, &packet.records[source], &decoded, &decoded.records[position]);
        }
    }

    // RFC 1035 §§2.3.4, 4.1.4 and RFC 3597 §4: validated suffixes become known boundaries.
    test "opaque maximum name publishes labels root and prefixed owner boundaries" {
        var name: wire.Name = undefined;
        try fixture.maxName(&name);
        var builder: fixture.Builder = undefined;
        builder.init();
        builder.record("\x00", 65400, .answer, name.wire());
        builder.record("\xc0\x17", 1, .additional, &.{ 127, 0, 0, 1 });
        builder.record("\x01x\xc0\x57", 1, .additional, &.{ 127, 0, 0, 1 });
        builder.record("\xc1\x15", 1, .additional, &.{ 127, 0, 0, 1 });
        var packet: wire.Packet = undefined;
        try packet.parse(try builder.finish());
        for ([_]usize{ 23, 87, 151, 215, 277 }) |offset| {
            try testing.expect(packet.boundaries.isSet(offset));
        }
        try packet.name(&name, packet.records[2].owner);
        try testing.expectEqual(193, name.length);
        try testing.expectEqualSlices(u8, "\x01x", name.wire()[0..2]);
        try packet.name(&name, packet.records[3].owner);
        try testing.expectEqualSlices(u8, "\x00", name.wire());
    }

    // RFC 1035 §4.1.4: only the target offset, not the whole referenced name, is 14 bits.
    test "opaque fallback validates name bytes beyond the pointer offset limit" {
        var builder: fixture.Builder = undefined;
        builder.init();
        const padding: [16349]u8 = @splat(42);
        builder.record("\x00", 65400, .answer, &padding);
        builder.record("\x00", 65400, .answer, "\x01x\x07example\x00");
        pointerRecord(&builder, 16383);
        var packet: wire.Packet = undefined;
        try packet.parse(try builder.finish());
        try testing.expectEqual(16383, packet.records[1].data_start);
        var name: wire.Name = undefined;
        try packet.name(&name, packet.records[2].owner);
        try testing.expectEqualSlices(u8, "\x01x\x07example\x00", name.wire());
        var workspace: wire.rewrite.Workspace = undefined;
        var output: [65535]u8 = undefined;
        var decoded: wire.Packet = undefined;
        try decoded.parse(try workspace.rewrite(&packet, &output, &.{}));
        for (0..packet.record_count) |index| {
            try equivalent(&packet, &packet.records[index], &decoded, &decoded.records[index]);
        }
    }

    // RFC 3597 §4 and SPEC §3.9: every name byte must stay in one prior opaque region.
    test "opaque fallback rejects label and terminator region escapes" {
        for ([_][]const u8{ "\x03a", "\x01a", "\x01a\x00" }) |data| {
            var builder: fixture.Builder = undefined;
            builder.init();
            builder.record("\x00", 65400, .answer, data);
            builder.record("\x00", 1, .answer, &.{ 127, 0, 0, 1 });
            // The last case targets the RDLENGTH low byte, not the RDATA region.
            const offset: u16 = if (data.len == 3) 22 else 23;
            pointerRecord(&builder, offset);
            var packet: wire.Packet = undefined;
            try testing.expectError(error.InvalidPointer, packet.parse(try builder.finish()));
        }
    }

    // RFC 3597 §4 and SPEC §3.9: unknown RDATA fallback never follows embedded pointers.
    test "opaque fallback rejects embedded pointers and publishes no partial boundaries" {
        var builder: fixture.Builder = undefined;
        builder.init();
        builder.question("\x00", 1, 1);
        builder.record("\x00", 65400, .answer, "\x01a\xc0\x0c");
        pointerRecord(&builder, 28);
        var packet: wire.Packet = undefined;
        try testing.expectError(error.InvalidPointer, packet.parse(try builder.finish()));
        var boundaries: wire.names.Boundaries = undefined;
        boundaries.init();
        for (28..32) |offset| boundaries.opaque_bytes.set(offset);
        var name: wire.Name = undefined;
        try testing.expectError(error.InvalidPointer, wire.names.decode(
            &name,
            builder.bytes[0..builder.cursor],
            32,
            builder.cursor,
            &boundaries,
            .allowed,
        ));
        try testing.expect(!boundaries.isSet(28));
        try testing.expect(!boundaries.isSet(30));
    }

    // RFC 1035 §2.3.4: opaque provenance cannot relax the label or expanded-name bounds.
    test "opaque fallback rejects oversized labels names and prefixed names" {
        var builder: fixture.Builder = undefined;
        var packet: wire.Packet = undefined;
        builder.init();
        builder.record("\x00", 65400, .answer, "\x40" ++ "a" ** 64 ++ "\x00");
        pointerRecord(&builder, 23);
        try testing.expectError(error.LabelTooLong, packet.parse(try builder.finish()));
        var name: wire.Name = undefined;
        try fixture.maxName(&name);
        builder.init();
        builder.record("\x00", 65400, .answer, name.wire());
        builder.record("\x01x\xc0\x17", 1, .additional, &.{ 127, 0, 0, 1 });
        try testing.expectError(error.NameTooLong, packet.parse(try builder.finish()));
        var oversized: [257]u8 = undefined;
        @memcpy(oversized[0..2], "\x01x");
        @memcpy(oversized[2..], name.wire());
        builder.init();
        builder.record("\x00", 65400, .answer, &oversized);
        pointerRecord(&builder, 23);
        try testing.expectError(error.NameTooLong, packet.parse(try builder.finish()));
    }

    // RFC 1035 §3.3 and RFC 6891 §6.1.2: known scalar/string/option bytes are not opaque.
    test "name shaped known scalar and string fields never supply pointer targets" {
        const Case = struct { kind: u16, data: []const u8, offset: u16 = 0 };
        const cases = [_]Case{
            .{ .kind = 1, .data = "\x01x\x00\x00" },
            .{ .kind = 28, .data = "\x01x\x00" ++ "\x00" ** 13 },
            .{ .kind = 13, .data = "\x03\x01x\x00\x00", .offset = 1 },
            .{ .kind = 16, .data = "\x03\x01x\x00", .offset = 1 },
            .{ .kind = 99, .data = "\x03\x01x\x00", .offset = 1 },
            .{ .kind = 41, .data = "\xfd\xe8\x00\x03\x01x\x00", .offset = 4 },
            .{ .kind = 15, .data = "\x00\x00\x00" },
            .{ .kind = 35, .data = "\x00\x00\x00\x00\x03\x01x\x00\x00\x00\x00", .offset = 5 },
        };
        for (cases) |case| {
            var builder: fixture.Builder = undefined;
            builder.init();
            builder.record("\x00", case.kind, .additional, case.data);
            pointerRecord(&builder, 23 + case.offset);
            var packet: wire.Packet = undefined;
            try testing.expectError(error.InvalidPointer, packet.parse(try builder.finish()));
        }
    }

    fn pointerRecord(builder: *fixture.Builder, offset: u16) void {
        var pointer: [2]u8 = undefined;
        wire.put(u16, &pointer, 0xc000 | offset);
        builder.record(&pointer, 1, .additional, &.{ 127, 0, 0, 1 });
    }
};
