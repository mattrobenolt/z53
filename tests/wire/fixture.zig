const wire = @import("wire");

pub const Builder = struct {
    bytes: [65535]u8,
    cursor: usize,
    header: wire.Header,

    pub fn init(self: *Builder) void {
        self.cursor = 12;
        self.header = .{ .id = 0xabcd, .bits = 0x8180 };
    }

    pub fn append(self: *Builder, data: []const u8) void {
        @memcpy(self.bytes[self.cursor..][0..data.len], data);
        self.cursor += data.len;
    }

    pub fn number(self: *Builder, comptime T: type, value: T) void {
        wire.put(T, self.bytes[self.cursor..][0..@sizeOf(T)], value);
        self.cursor += @sizeOf(T);
    }

    pub fn question(self: *Builder, name: []const u8, kind: u16, class: u16) void {
        self.append(name);
        self.number(u16, kind);
        self.number(u16, class);
        self.header.counts[0] += 1;
    }

    pub fn record(
        self: *Builder,
        owner: []const u8,
        kind: u16,
        section: wire.Section,
        data: []const u8,
    ) void {
        self.append(owner);
        self.number(u16, kind);
        self.number(u16, 1);
        self.number(u32, 30);
        self.number(u16, @intCast(data.len));
        self.append(data);
        self.header.counts[@intFromEnum(section)] += 1;
    }

    pub fn finish(self: *Builder) wire.Error![]u8 {
        try self.header.encode(&self.bytes);
        return self.bytes[0..self.cursor];
    }
};

pub fn maxName(target: *wire.Name) wire.Error!void {
    target.length = 0;
    const label = [_]u8{'a'} ** 63;
    for ([_]u8{ 63, 63, 63, 61 }) |length| {
        try target.append(&.{length});
        try target.append(label[0..length]);
    }
    try target.append(&.{0});
}
