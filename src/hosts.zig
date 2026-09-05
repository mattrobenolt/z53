//! Bounded, caller-owned hosts snapshots. Only replacement writes the inactive table.
const std = @import("std");
const wire = @import("wire.zig");

pub const source_bytes_max = 1024 * 1024;
pub const entries_max = 4096;
pub const Error = error{ SourceTooLarge, TableFull };
pub const Reload = enum { unchanged, replaced };
const Address = union(enum) { ipv4: [4]u8, ipv6: [16]u8 };
pub const Entry = struct {
    name: wire.Name,
    reverse: wire.Name,
    address: Address,

    pub fn matches(self: *const Entry, name: *const wire.Name, kind: u16) bool {
        return switch (kind) {
            1 => switch (self.address) {
                .ipv4 => self.name.equal(name),
                .ipv6 => false,
            },
            28 => switch (self.address) {
                .ipv4 => false,
                .ipv6 => self.name.equal(name),
            },
            12 => self.reverse.equal(name),
            else => false,
        };
    }

    pub fn write(self: *const Entry, encoder: *wire.Encoder, kind: u16) wire.Error!void {
        switch (kind) {
            1 => try encoder.bytes(&self.address.ipv4),
            28 => try encoder.bytes(&self.address.ipv6),
            12 => try encoder.name(&self.name, .allowed),
            else => unreachable,
        }
    }
};

pub const Table = struct {
    storage: []Entry,
    count: u16 = 0,

    pub fn entries(self: *const Table) []const Entry {
        return self.storage[0..self.count];
    }

    /// Failure invalidates this candidate, never the Store's active snapshot.
    fn parse(self: *Table, source: []const u8) Error!void {
        std.debug.assert(self.storage.len <= entries_max);
        self.count = 0;
        if (source.len > source_bytes_max) return error.SourceTooLarge;
        var lines = std.mem.splitScalar(u8, source, '\n');
        while (lines.next()) |text| try self.line(text);
    }

    fn line(self: *Table, text: []const u8) Error!void {
        const end = std.mem.indexOfScalar(u8, text, '#') orelse text.len;
        var tokens = std.mem.tokenizeAny(u8, text[0..end], " \t\r");
        const literal = tokens.next() orelse return;
        var address: Address = undefined;
        if (std.Io.net.Ip4Address.parse(literal, 0)) |value| {
            address = .{ .ipv4 = value.bytes };
        } else |_| {
            const value = std.Io.net.Ip6Address.parse(literal, 0) catch return;
            // A scoped address cannot be represented in DNS AAAA RDATA.
            if (std.mem.indexOfScalar(u8, literal, '%') != null) return;
            address = .{ .ipv6 = value.bytes };
        }
        const aliases = tokens;
        var name: wire.Name = undefined;
        while (tokens.next()) |text_name| {
            parseName(&name, text_name) catch return;
        }
        var reverse: wire.Name = undefined;
        reverseName(&reverse, &address);
        tokens = aliases;
        while (tokens.next()) |text_name| {
            parseName(&name, text_name) catch unreachable;
            if (self.contains(&name, &reverse)) continue;
            if (self.count == self.storage.len) return error.TableFull;
            self.storage[self.count] = .{ .name = name, .reverse = reverse, .address = address };
            self.count += 1;
        }
    }

    fn contains(self: *const Table, name: *const wire.Name, reverse: *const wire.Name) bool {
        for (self.entries()) |*entry| {
            if (!entry.name.equal(name)) continue;
            if (entry.reverse.equal(reverse)) return true;
        }
        return false;
    }
};

/// The event thread must complete readers before replacement or reuse of snapshots.
/// The runtime schedules load calls; no timer or asynchronous snapshot is owned here.
pub const Store = struct {
    tables: [2]Table,
    active: u1 = 0,
    mtime: ?i128 = null,

    pub fn init(self: *Store, first: []Entry, second: []Entry) void {
        std.debug.assert(first.len > 0);
        std.debug.assert(first.len == second.len);
        std.debug.assert(first.len <= entries_max);
        const first_end = @intFromPtr(first.ptr) + first.len * @sizeOf(Entry);
        const second_end = @intFromPtr(second.ptr) + second.len * @sizeOf(Entry);
        if (@intFromPtr(first.ptr) < @intFromPtr(second.ptr)) {
            std.debug.assert(first_end <= @intFromPtr(second.ptr));
        } else std.debug.assert(second_end <= @intFromPtr(first.ptr));
        self.* = .{ .tables = .{ .{ .storage = first }, .{ .storage = second } } };
    }

    pub fn table(self: *const Store) *const Table {
        return &self.tables[self.active];
    }

    pub fn changed(self: *const Store, mtime: i128) bool {
        return self.mtime != mtime;
    }

    /// Caller supplies source_bytes_max + 1 bytes to detect growth beyond the bound.
    /// Read one opened regular file; a changed file is retried on the next check.
    pub fn load(
        self: *Store,
        io: std.Io,
        directory: std.Io.Dir,
        path: []const u8,
        buffer: []u8,
    ) (Error || std.Io.File.OpenError || std.Io.File.StatError ||
        std.Io.Dir.StatFileError || std.Io.File.ReadPositionalError ||
        error{ NotRegularFile, FileChanged })!Reload {
        std.debug.assert(buffer.len > source_bytes_max);
        // Reject configured devices/FIFOs before open, which can otherwise block.
        const path_stat = try directory.statFile(io, path, .{});
        if (path_stat.kind != .file) return error.NotRegularFile;
        if (!self.changed(path_stat.mtime.nanoseconds)) return .unchanged;
        const file = try directory.openFile(io, path, .{});
        defer file.close(io);
        const before = try file.stat(io);
        if (before.kind != .file) return error.NotRegularFile;
        if (!self.changed(before.mtime.nanoseconds)) return .unchanged;
        if (before.size > source_bytes_max) return error.SourceTooLarge;
        const length = try file.readPositionalAll(io, buffer[0 .. source_bytes_max + 1], 0);
        if (length > source_bytes_max) return error.SourceTooLarge;
        const after = try file.stat(io);
        if (before.mtime.nanoseconds != after.mtime.nanoseconds) return error.FileChanged;
        if (before.ctime.nanoseconds != after.ctime.nanoseconds) return error.FileChanged;
        if (before.size != after.size) return error.FileChanged;
        if (length != after.size) return error.FileChanged;
        try self.replace(buffer[0..length], before.mtime.nanoseconds);
        return .replaced;
    }

    /// Publish only a complete parse. Failure preserves the old mtime for retries.
    pub fn replace(self: *Store, source: []const u8, mtime: i128) Error!void {
        const candidate = self.active ^ 1;
        try self.tables[candidate].parse(source);
        self.active = candidate;
        self.mtime = mtime;
    }
};

fn parseName(target: *wire.Name, text: []const u8) wire.Error!void {
    for (text) |byte| {
        if (std.ascii.isAlphanumeric(byte)) continue;
        switch (byte) {
            '-', '_', '.' => {},
            else => return error.InvalidName,
        }
    }
    try target.fromText(text);
    if (target.length == 1) return error.InvalidName;
    for (target.bytes[0..target.length]) |*byte| byte.* = std.ascii.toLower(byte.*);
}

fn reverseName(target: *wire.Name, address: *const Address) void {
    var text: [80]u8 = undefined;
    switch (address.*) {
        .ipv4 => |bytes| {
            const value = std.fmt.bufPrint(&text, "{d}.{d}.{d}.{d}.in-addr.arpa.", .{
                bytes[3], bytes[2], bytes[1], bytes[0],
            }) catch unreachable;
            target.fromText(value) catch unreachable;
        },
        .ipv6 => |bytes| {
            const digits = "0123456789abcdef";
            for (0..16) |index| {
                const byte = bytes[15 - index];
                text[index * 4 ..][0..4].* = .{ digits[byte & 15], '.', digits[byte >> 4], '.' };
            }
            @memcpy(text[64..73], "ip6.arpa.");
            target.fromText(text[0..73]) catch unreachable;
        },
    }
}
