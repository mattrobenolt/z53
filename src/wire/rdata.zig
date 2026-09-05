const wire = @import("../wire.zig");
const names = wire.names;

pub const Range = struct { start: u16, end: u16 };
pub const NamePart = struct { offset: u16, compression: names.Compression };
pub const Part = union(enum) { bytes: Range, name: NamePart };
pub const Parts = struct {
    items: [7]Part,
    count: u8,

    fn add(self: *Parts, part: Part) void {
        self.items[self.count] = part;
        self.count += 1;
    }
};

/// RFC 3597 §4 lists all historical compression-capable layouts.
/// Legacy non-1035 names decode compression but never emit it.
pub fn parse(target: *Parts, packet: *wire.Packet, record: *const wire.Record) wire.Error!void {
    target.count = 0;
    var cursor: usize = record.data_start;
    const end: usize = record.data_end;
    switch (record.kind) {
        2, 3, 4, 5, 7, 8, 9, 12 => try name(target, packet, &cursor, end, .allowed, .allowed),
        6 => {
            try name(target, packet, &cursor, end, .allowed, .allowed);
            try name(target, packet, &cursor, end, .allowed, .allowed);
            try bytes(target, packet.bytes, &cursor, end, 20);
        },
        14, 17 => {
            const output: names.Compression = if (record.kind == 14) .allowed else .forbidden;
            try name(target, packet, &cursor, end, .allowed, output);
            try name(target, packet, &cursor, end, .allowed, output);
        },
        15, 18, 21, 36 => {
            try bytes(target, packet.bytes, &cursor, end, 2);
            const input: names.Compression = if (record.kind == 36) .forbidden else .allowed;
            const output: names.Compression = if (record.kind == 15) .allowed else .forbidden;
            try name(target, packet, &cursor, end, input, output);
        },
        24, 46 => try signature(target, packet, &cursor, end, record.kind),
        26 => {
            try bytes(target, packet.bytes, &cursor, end, 2);
            try name(target, packet, &cursor, end, .allowed, .forbidden);
            try name(target, packet, &cursor, end, .allowed, .forbidden);
        },
        30, 47 => {
            const input: names.Compression = if (record.kind == 30) .allowed else .forbidden;
            try name(target, packet, &cursor, end, input, .forbidden);
            try bytes(target, packet.bytes, &cursor, end, end - cursor);
        },
        33 => {
            try bytes(target, packet.bytes, &cursor, end, 6);
            try name(target, packet, &cursor, end, .allowed, .forbidden);
        },
        35 => try naptr(target, packet, &cursor, end),
        23 => try name(target, packet, &cursor, end, .allowed, .forbidden),
        39 => try name(target, packet, &cursor, end, .forbidden, .forbidden),
        else => try opaqueData(target, packet, record, &cursor, end),
    }
    if (cursor != end) return error.InvalidRecord;
}

fn name(
    parts: *Parts,
    packet: *wire.Packet,
    cursor: *usize,
    end: usize,
    input: names.Compression,
    output: names.Compression,
) wire.Error!void {
    var expanded: names.Name = undefined;
    const offset: u16 = @intCast(cursor.*);
    cursor.* = try names.decode(&expanded, packet.bytes, cursor.*, end, &packet.boundaries, input);
    parts.add(.{ .name = .{ .offset = offset, .compression = output } });
}

fn bytes(
    parts: *Parts,
    packet: []const u8,
    cursor: *usize,
    end: usize,
    length: usize,
) wire.Error!void {
    const start: u16 = @intCast(cursor.*);
    _ = try wire.take(packet[0..end], cursor, length);
    parts.add(.{ .bytes = .{ .start = start, .end = @intCast(cursor.*) } });
}

fn signature(
    parts: *Parts,
    packet: *wire.Packet,
    cursor: *usize,
    end: usize,
    kind: u16,
) wire.Error!void {
    try bytes(parts, packet.bytes, cursor, end, 18);
    const input: names.Compression = if (kind == 24) .allowed else .forbidden;
    try name(parts, packet, cursor, end, input, .forbidden);
    try bytes(parts, packet.bytes, cursor, end, end - cursor.*);
}

fn naptr(parts: *Parts, packet: *wire.Packet, cursor: *usize, end: usize) wire.Error!void {
    try bytes(parts, packet.bytes, cursor, end, 4);
    for (0..3) |_| {
        if (cursor.* >= end) return error.Truncated;
        try bytes(parts, packet.bytes, cursor, end, @as(usize, packet.bytes[cursor.*]) + 1);
    }
    try name(parts, packet, cursor, end, .allowed, .forbidden);
}

fn opaqueData(
    parts: *Parts,
    packet: *wire.Packet,
    record: *const wire.Record,
    cursor: *usize,
    end: usize,
) wire.Error!void {
    const length = end - cursor.*;
    if (record.class == 1) {
        switch (record.kind) {
            1 => if (length != 4) return error.InvalidRecord,
            28 => if (length != 16) return error.InvalidRecord,
            else => {},
        }
    }
    // Character strings are bounded independently of the surrounding RDLENGTH.
    switch (record.kind) {
        13 => {
            try strings(packet.bytes[cursor.*..end], 2);
        },
        16, 99 => {
            if (length == 0) return error.InvalidRecord;
            try strings(packet.bytes[cursor.*..end], null);
        },
        else => {},
    }
    if (unknownLayout(record)) {
        // Headers separate RDATA ranges, so adjacent set bits stay in one record.
        for (cursor.*..end) |offset| packet.boundaries.opaque_bytes.set(offset);
    }
    try bytes(parts, packet.bytes, cursor, end, length);
}

fn unknownLayout(record: *const wire.Record) bool {
    switch (record.kind) {
        10, 13, 16, 41, 99 => return false,
        1, 11, 28 => return record.class != 1,
        else => return true,
    }
}

fn strings(data: []const u8, expected: ?u16) wire.Error!void {
    var cursor: usize = 0;
    var count: u16 = 0;
    while (cursor < data.len) : (count += 1) {
        const length = data[cursor];
        cursor += 1;
        _ = try wire.take(data, &cursor, length);
    }
    if (expected) |wanted| {
        if (count != wanted) return error.InvalidRecord;
    }
}
