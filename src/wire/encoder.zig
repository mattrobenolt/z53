const std = @import("std");
const wire = @import("../wire.zig");
const names = wire.names;

/// Output and input must not overlap. Any error invalidates this encoder.
/// Every compression entry refers to the current output, never the input.
pub const Encoder = struct {
    output: []u8,
    cursor: usize,
    header: wire.Header,
    dictionary: [16384]u16,
    boundaries: names.Boundaries,
    section: wire.Section,

    pub fn init(self: *Encoder, output: []u8, header: *const wire.Header) wire.Error!void {
        if (output.len < 12) return error.NoSpace;
        self.output = output[0..@min(output.len, wire.message_bytes_max)];
        self.cursor = 12;
        self.header = header.*;
        self.header.counts = @splat(0);
        self.dictionary = @splat(0);
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
                    try self.number(u16, 0xc000 | offset);
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
            if (offset >= 16384) break;
            self.boundaries.set(offset);
            if (suffix + 1 == value.length) break;
            self.insert(value.wire()[suffix..], @intCast(offset));
            suffix += @as(usize, value.bytes[suffix]) + 1;
        }
    }

    fn lookup(self: *Encoder, suffix: []const u8) ?u16 {
        const hash = std.hash.Wyhash.hash(0, suffix);
        for (0..self.dictionary.len) |probe| {
            const slot = (hash +% probe) % self.dictionary.len;
            const offset = self.dictionary[slot];
            if (offset == 0) return null;
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
        const hash = std.hash.Wyhash.hash(0, suffix);
        for (0..self.dictionary.len) |probe| {
            const slot = (hash +% probe) % self.dictionary.len;
            if (self.dictionary[slot] != 0) continue;
            self.dictionary[slot] = offset;
            return;
        }
        // Saturation reduces compression only; offsets never alias new data.
    }

    pub fn question(
        self: *Encoder,
        value: *const wire.Name,
        kind: u16,
        class: u16,
    ) wire.Error!void {
        if (self.section != .question) return error.InvalidOrder;
        try self.name(value, .allowed);
        try self.number(u16, kind);
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
        try self.number(u16, value.kind);
        try self.number(u16, value.class);
        try self.number(u32, value.ttl_s);
        const offset = self.cursor;
        try self.number(u16, 0);
        self.header.counts[@intFromEnum(value.section)] += 1;
        return offset;
    }

    pub fn endRecord(self: *Encoder, length_offset: usize) void {
        std.debug.assert(length_offset + 2 <= self.cursor);
        const length: u16 = @intCast(self.cursor - length_offset - 2);
        wire.put(u16, self.output[length_offset..][0..2], length);
    }

    pub fn record(self: *Encoder, packet: *wire.Packet, value: *const wire.Record) wire.Error!void {
        var owner: wire.Name = undefined;
        try packet.name(&owner, value.owner);
        const length_offset = try self.beginRecord(&owner, value);
        var parts: wire.rdata.Parts = undefined;
        try wire.rdata.parse(&parts, packet, value);
        for (parts.items[0..parts.count]) |part| {
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
