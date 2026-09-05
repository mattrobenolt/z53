const std = @import("std");

pub const Error = error{
    Truncated,
    LabelTooLong,
    NameTooLong,
    InvalidPointer,
    CompressionForbidden,
    InvalidName,
};
pub const Compression = enum { allowed, forbidden };
pub const Boundaries = struct {
    labels: std.StaticBitSet(16384),
    opaque_bytes: std.StaticBitSet(65536),

    pub fn init(self: *Boundaries) void {
        self.* = .{ .labels = .initEmpty(), .opaque_bytes = .initEmpty() };
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
    bytes: [255]u8 = undefined,
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
        if (text.len > 254) return error.NameTooLong;
        const end = text.len - @intFromBool(text[text.len - 1] == '.');
        var labels = std.mem.splitScalar(u8, text[0..end], '.');
        while (labels.next()) |label| {
            if (label.len == 0) return error.InvalidName;
            if (label.len > 63) return error.LabelTooLong;
            try self.append(&.{@intCast(label.len)});
            try self.append(label);
        }
        try self.append(&.{0});
    }

    pub fn append(self: *Name, bytes: []const u8) Error!void {
        const end = @as(usize, self.length) + bytes.len;
        if (end > 255) return error.NameTooLong;
        @memcpy(self.bytes[self.length..end], bytes);
        self.length = @intCast(end);
    }

    pub fn validate(self: *const Name) Error!void {
        var index: usize = 0;
        while (index < self.length) {
            const length = self.bytes[index];
            if (length > 63) return error.LabelTooLong;
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

    pub fn equal(self: *const Name, other: *const Name) bool {
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
    target.length = 0;
    if (end > packet.len) return error.Truncated;
    if (packet.len > 65535) return error.InvalidName;
    var cursor = start;
    var ceiling = end;
    var consumed: ?usize = null;
    var steps: u16 = 0;
    while (steps < 16512) : (steps += 1) {
        if (cursor >= ceiling) return error.Truncated;
        const length = packet[cursor];
        if (length & 0xc0 == 0xc0) {
            if (compression == .forbidden) return error.CompressionForbidden;
            if (cursor + 2 > ceiling) return error.Truncated;
            const pointer = (@as(usize, length & 0x3f) << 8) | packet[cursor + 1];
            if (pointer >= cursor) return error.InvalidPointer;
            if (!boundaries.isSet(pointer)) {
                try decodeOpaque(target, packet, pointer, cursor, boundaries);
                mark(boundaries, cursor);
                return consumed orelse cursor + 2;
            }
            if (consumed == null) consumed = cursor + 2;
            mark(boundaries, cursor);
            ceiling = cursor;
            cursor = pointer;
            continue;
        }
        if (length > 63) return error.LabelTooLong;
        const next = cursor + 1 + @as(usize, length);
        if (next > ceiling) return error.Truncated;
        mark(boundaries, cursor);
        try target.append(packet[cursor..next]);
        cursor = next;
        if (length == 0) return consumed orelse cursor;
    }
    return error.InvalidPointer;
}

fn mark(boundaries: *Boundaries, offset: usize) void {
    if (offset < 16384) boundaries.set(offset);
}

fn decodeOpaque(
    target: *Name,
    packet: []const u8,
    start: usize,
    ceiling: usize,
    boundaries: *Boundaries,
) Error!void {
    var suffix: Name = .{ .length = 0 };
    var cursor = start;
    while (cursor < ceiling) {
        if (!boundaries.opaque_bytes.isSet(cursor)) return error.InvalidPointer;
        const length = packet[cursor];
        if (length & 0xc0 == 0xc0) return error.InvalidPointer;
        if (length > 63) return error.LabelTooLong;
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
        var offset = start;
        while (offset < cursor) {
            mark(boundaries, offset);
            offset += @as(usize, packet[offset]) + 1;
        }
        return;
    }
    return error.InvalidPointer;
}
