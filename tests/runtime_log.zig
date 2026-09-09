const std = @import("std");
const runtime = @import("runtime");
const testing = std.testing;
const log = runtime.log;
const wire = runtime.pipeline.wire;

pub const Capture = struct {
    storage: [16384]u8 = undefined,
    length: usize = 0,
    mode: enum { capture, fail } = .capture,
    attempts: u32 = 0,

    pub fn sink(self: *Capture) log.Sink {
        return .{ .context = self, .write = write };
    }

    fn write(_: std.Io, context: ?*anyopaque, line: []const u8) error{WriteFailed}!void {
        const self: *Capture = @ptrCast(@alignCast(context.?));
        self.attempts += 1;
        if (self.mode == .fail) return error.WriteFailed;
        if (line.len > self.storage.len - self.length) return error.WriteFailed;
        @memcpy(self.storage[self.length..][0..line.len], line);
        self.length += line.len;
    }

    pub fn bytes(self: *const Capture) []const u8 {
        return self.storage[0..self.length];
    }

    pub fn count(self: *const Capture, needle: []const u8) usize {
        return std.mem.count(u8, self.bytes(), needle);
    }

    pub fn contains(self: *const Capture, needle: []const u8) !void {
        try testing.expect(std.mem.indexOf(u8, self.bytes(), needle) != null);
    }

    pub fn client(self: *const Capture, descriptor: std.c.fd_t, protocol: log.Protocol) !void {
        var address: std.c.sockaddr.storage = undefined;
        var length: std.c.socklen_t = @sizeOf(std.c.sockaddr.storage);
        try testing.expectEqual(0, std.c.getsockname(descriptor, @ptrCast(&address), &length));
        var buffer: [128]u8 = undefined;
        const expected = try std.fmt.bufPrint(&buffer, "proto={s} client={f} ", .{
            @tagName(protocol), log.peer(&address, length).?,
        });
        try self.contains(expected);
    }
};

fn request(output: []u8, name: *const wire.Name, kind: u16) ![]const u8 {
    var encoder: wire.Encoder = undefined;
    try encoder.init(output, &.{ .id = 42, .bits = 0x100 });
    try encoder.question(name, @enumFromInt(kind), 1);
    return encoder.finish();
}

// SPEC §4, RFC 6891 §6.1.3: full numeric RCODE, numeric QTYPE, UTC, and monotonic elapsed time.
test "logging formatter timestamp duration extended rcode and numeric qtype" {
    const packet = try testing.allocator.create(wire.Packet);
    defer testing.allocator.destroy(packet);
    var name: wire.Name = undefined;
    try name.fromText("example.com.");
    var input: [512]u8 = undefined;
    const query = try request(&input, &name, 65280);
    var response: [512]u8 = undefined;
    @memcpy(response[0..query.len], query);
    response[2] = 0x81;
    response[3] = 0x8f;
    response[11] = 1;
    const opt = [_]u8{ 0, 0, 41, 4, 208, 0xab, 0, 0, 0, 0, 0 };
    @memcpy(response[query.len..][0..opt.len], &opt);
    var buffer: [log.line_bytes_max]u8 = undefined;
    const bytes = try log.format(&buffer, packet, &.{
        .client = try std.Io.net.IpAddress.parse("127.0.0.1", 44123),
        .protocol = .udp,
        .started_ns = 1000000,
    }, query, &.{ .bytes = response[0 .. query.len + opt.len], .source = .forward }, &.{
        .address = try std.Io.net.IpAddress.parse("1.1.1.1", 853),
        .protocol = .dot,
        .tls_name = "one.one.one.one",
    }, .{ .unix_ms = 1788570753512, .finished_ns = 2234567 });
    try testing.expectEqualStrings(
        "2026-09-05T01:12:33.512Z event=query proto=udp client=127.0.0.1:44123 " ++
            "qtype=65280 qname=\"example.com.\" rcode=2751 duration_ms=1.234 src=forward " ++
            "upstream=1.1.1.1:853 upstream_proto=dot tls_name=\"one.one.one.one\"\n",
        bytes,
    );
}

// SPEC §4: every hostile label byte remains data within exactly one bounded line.
test "logging formatter hostile maximum name and local source has no upstream" {
    const packet = try testing.allocator.create(wire.Packet);
    defer testing.allocator.destroy(packet);
    var name: wire.Name = .{};
    const hostile: [63]u8 = @splat(0x1b);
    for ([_]u8{ 63, 63, 63, 61 }) |length| {
        try name.append(&.{length});
        try name.append(hostile[0..length]);
    }
    try name.append(&.{0});
    name.bytes[1] = '\n';
    name.bytes[2] = '\r';
    name.bytes[3] = 0;
    name.bytes[4] = '.';
    name.bytes[5] = '"';
    name.bytes[6] = '\\';
    name.bytes[7] = 0xff;
    try testing.expectEqual(255, name.length);
    var input: [512]u8 = undefined;
    const query = try request(&input, &name, 65535);
    var buffer: [log.line_bytes_max]u8 = undefined;
    const bytes = try log.format(&buffer, packet, &.{
        .client = try std.Io.net.IpAddress.parse("::1", 1234),
        .protocol = .tcp,
        .started_ns = 500,
    }, query, &.{ .bytes = query, .source = .cache }, &.{
        .address = try std.Io.net.IpAddress.parse("1.1.1.1", 853),
        .protocol = .dot,
        .tls_name = "unused.example",
    }, .{ .unix_ms = 0, .finished_ns = 0 });
    try testing.expect(std.mem.indexOf(u8, bytes, "\\x0a\\x0d\\x00\\x2e\\x22\\x5c\\xff") != null);
    try testing.expectEqual(1, std.mem.count(u8, bytes, "\n"));
    try testing.expect(std.mem.indexOfScalar(u8, bytes, 0x1b) == null);
    try testing.expect(std.mem.indexOf(u8, bytes, "upstream") == null);
    try testing.expect(std.mem.indexOf(u8, bytes, "client=[::1]:1234") != null);
    try testing.expect(std.mem.indexOf(u8, bytes, "duration_ms=0.000 src=cache") != null);
    const hostile_tls: [253]u8 = @splat(0x1b);
    const forwarded = try log.format(&buffer, packet, &.{
        .client = try std.Io.net.IpAddress.parse("::1", 65535),
        .protocol = .tcp,
        .started_ns = 0,
    }, query, &.{ .bytes = query, .source = .forward }, &.{
        .address = try std.Io.net.IpAddress.parse("::1", 853),
        .protocol = .dot,
        .tls_name = &hostile_tls,
    }, .{ .unix_ms = 0, .finished_ns = std.math.maxInt(u64) });
    try testing.expect(forwarded.len < log.line_bytes_max);
    try testing.expectEqual(1, std.mem.count(u8, forwarded, "\n"));
    try testing.expect(std.mem.indexOfScalar(u8, forwarded, 0x1b) == null);
}

// SPEC §§1.10, 4: sequential log events retain storage but expose only the current line.
test "logging retained workspace preserves dirty tail across event kinds and sink failure" {
    const packet = try testing.allocator.create(wire.Packet);
    defer testing.allocator.destroy(packet);
    var capture: Capture = .{};
    var logger: log.Logger = .{ .sink = capture.sink() };
    @memset(&logger.buffer, 0xa5);
    var name: wire.Name = undefined;
    try name.fromText("retained.log.example.");
    var input: [512]u8 = undefined;
    const query = try request(&input, &name, 1);
    const observation: log.Query = .{ .client = null, .protocol = .udp, .started_ns = 0 };
    const answer: runtime.pipeline.resolver.Answer = .{ .bytes = query, .source = .cache };
    log.completed(&logger, testing.io, packet, &observation, query, &answer, null, 0);
    try testing.expectEqual(1, capture.attempts);
    try capture.contains("qname=\"retained.log.example.\"");
    var extent = capture.length;
    for (logger.buffer[extent..]) |byte| try testing.expectEqual(@as(u8, 0xa5), byte);
    const upstream: log.Upstream = .{
        .address = try std.Io.net.IpAddress.parse("127.0.0.1", 53),
        .protocol = .udp,
    };
    capture.length = 0;
    log.failure(&logger, testing.io, &upstream, .transport_failure);
    try testing.expectEqual(1, capture.count("\n"));
    try testing.expectEqual(0, capture.count("retained.log.example"));
    extent = @max(extent, capture.length);
    for (logger.buffer[extent..]) |byte| try testing.expectEqual(@as(u8, 0xa5), byte);
    capture.length = 0;
    capture.mode = .fail;
    log.health(&logger, testing.io, &upstream, .down, 2);
    try testing.expectEqual(0, capture.length);
    capture.mode = .capture;
    log.completed(&logger, testing.io, packet, &observation, query, &answer, null, 0);
    try testing.expectEqual(4, capture.attempts);
    try testing.expectEqual(1, capture.count("\n"));
    try testing.expectEqual(0, capture.count("event=upstream_health"));
    try capture.contains("src=cache");
}

// SPEC §§3.9, 4: malformed packets log placeholders and a failing sink returns
// no error to the caller.
test "logging malformed query reply and failed capture sink" {
    const packet = try testing.allocator.create(wire.Packet);
    defer testing.allocator.destroy(packet);
    var buffer: [log.line_bytes_max]u8 = undefined;
    const observation: log.Query = .{ .client = null, .protocol = .udp, .started_ns = 0 };
    const malformed = [_]u8{ 0, 42, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
    var reply: [12]u8 = undefined;
    try wire.malformed(&malformed).formerr.encode(&reply);
    const result: runtime.pipeline.resolver.Answer = .{ .bytes = &reply, .source = .servfail };
    const bytes = try log.format(
        &buffer,
        packet,
        &observation,
        &malformed,
        &result,
        null,
        .{ .unix_ms = 0, .finished_ns = 0 },
    );
    try testing.expect(std.mem.indexOf(u8, bytes, "qtype=unknown qname=unknown rcode=1") != null);
    const broken = try log.format(
        &buffer,
        packet,
        &observation,
        &malformed,
        &.{ .bytes = &.{1}, .source = .servfail },
        null,
        .{ .unix_ms = -1, .finished_ns = 0 },
    );
    try testing.expect(std.mem.indexOf(u8, broken, "rcode=unknown") != null);
    var capture: Capture = .{ .mode = .fail };
    var logger: log.Logger = .{ .sink = capture.sink() };
    log.completed(&logger, testing.io, packet, &observation, &malformed, &result, null, 0);
    try testing.expectEqual(1, capture.attempts);
    try testing.expectEqual(0, capture.length);
    try testing.expectEqual(1, (try wire.Header.decode(&reply)).bits & 15);
}
