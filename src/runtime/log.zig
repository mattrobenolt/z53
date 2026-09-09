//! #1: bounded, synchronous completion logs. Sink failures never change DNS outcomes.
const std = @import("std");
const resolver = @import("../resolver.zig");
const wire = resolver.wire;
const system = std.c;
pub const line_bytes_max = 3072;
pub const Protocol = enum { udp, tcp, dot };
pub const Query = struct {
    client: ?std.Io.net.IpAddress,
    protocol: Protocol,
    started_ns: u64,
};
pub const Upstream = struct {
    address: std.Io.net.IpAddress,
    protocol: Protocol,
    tls_name: ?[]const u8 = null,
};
pub const Sink = struct {
    context: ?*anyopaque = null,
    write: *const fn (std.Io, ?*anyopaque, []const u8) error{WriteFailed}!void = stderr,

    fn stderr(io: std.Io, _: ?*anyopaque, bytes: []const u8) error{WriteFailed}!void {
        // One bounded write avoids retry loops. A short write loses the remainder.
        _ = std.Io.File.stderr().writeStreaming(io, &.{}, &.{bytes}, 1) catch
            return error.WriteFailed;
    }
};

/// The event thread owns this workspace. Each synchronous sink call consumes its borrowed bytes.
/// Sink callbacks must not call logging functions on the same logger.
pub const Logger = struct {
    sink: Sink = .{},
    buffer: [line_bytes_max]u8 = undefined,
};

pub fn peer(
    storage: *const system.sockaddr.storage,
    length: system.socklen_t,
) ?std.Io.net.IpAddress {
    switch (storage.family) {
        system.AF.INET => {
            if (length != @sizeOf(system.sockaddr.in)) return null;
            const value: *const system.sockaddr.in = @ptrCast(storage);
            return .{ .ip4 = .{
                .bytes = @bitCast(value.addr),
                .port = std.mem.bigToNative(u16, value.port),
            } };
        },
        system.AF.INET6 => {
            if (length != @sizeOf(system.sockaddr.in6)) return null;
            const value: *const system.sockaddr.in6 = @ptrCast(storage);
            return .{ .ip6 = .{
                .bytes = value.addr,
                .port = std.mem.bigToNative(u16, value.port),
                .flow = value.flowinfo,
                .interface = .{ .index = value.scope_id },
            } };
        },
        else => return null,
    }
}

pub fn completed(
    logger: *Logger,
    io: std.Io,
    packet: *wire.Packet,
    query: *const Query,
    input: []const u8,
    answer: *const resolver.Answer,
    upstream: ?*const Upstream,
    finished_ns: u64,
) void {
    const bytes = format(&logger.buffer, packet, query, input, answer, upstream, .{
        .unix_ms = std.Io.Timestamp.now(io, .real).toMilliseconds(),
        .finished_ns = finished_ns,
    }) catch return;
    logger.sink.write(io, logger.sink.context, bytes) catch return;
}

pub const Time = struct { unix_ms: i64, finished_ns: u64 };
pub fn format(
    buffer: *[line_bytes_max]u8,
    packet: *wire.Packet,
    query: *const Query,
    input: []const u8,
    answer: *const resolver.Answer,
    upstream: ?*const Upstream,
    time: Time,
) std.Io.Writer.Error![]const u8 {
    var writer: std.Io.Writer = .fixed(buffer);
    try timestamp(&writer, time.unix_ms);
    try writer.print(" event=query proto={s} client=", .{@tagName(query.protocol)});
    if (query.client) |client| {
        try writer.print("{f}", .{client});
    } else try writer.writeAll("unknown");
    try question(&writer, packet, input);
    try writer.writeAll(" rcode=");
    if (packet.parse(answer.bytes)) |_| {
        var rcode: u16 = packet.header.bits & 15;
        if (packet.opt) |index| rcode |= @as(u16, @intCast(packet.records[index].ttl_s >> 24)) << 4;
        try writer.print("{d}", .{rcode});
    } else |_| try writer.writeAll("unknown");
    const elapsed_ns = time.finished_ns -| query.started_ns;
    try writer.print(" duration_ms={d}.{d:0>3} src={s}", .{
        elapsed_ns / std.time.ns_per_ms,
        (elapsed_ns % std.time.ns_per_ms) / std.time.ns_per_us,
        @tagName(answer.source),
    });
    if (answer.source == .forward) {
        if (upstream) |selected| try upstreamFields(&writer, selected);
    }
    try writer.writeByte('\n');
    return writer.buffered();
}

fn question(
    writer: *std.Io.Writer,
    packet: *wire.Packet,
    input: []const u8,
) std.Io.Writer.Error!void {
    packet.parse(input) catch return writer.writeAll(" qtype=unknown qname=unknown");
    if (packet.header.counts[0] != 1) return writer.writeAll(" qtype=unknown qname=unknown");
    var cursor: usize = 12;
    const value = packet.readQuestion(&cursor) catch
        return writer.writeAll(" qtype=unknown qname=unknown");
    var name: wire.Name = undefined;
    packet.name(&name, value.name) catch return writer.writeAll(" qtype=unknown qname=unknown");
    try writer.print(" qtype={d} qname=\"", .{value.kind});
    var offset: u16 = 0;
    while (offset < name.length) {
        const length = name.bytes[offset];
        offset += 1;
        if (length == 0) {
            if (offset == 1) try writer.writeByte('.');
            break;
        }
        try escaped(writer, name.bytes[offset..][0..length], .label);
        try writer.writeByte('.');
        offset += length;
    }
    try writer.writeByte('"');
}

fn escaped(
    writer: *std.Io.Writer,
    bytes: []const u8,
    mode: enum { label, text },
) std.Io.Writer.Error!void {
    for (bytes) |byte| {
        switch (byte) {
            'a'...'z', 'A'...'Z', '0'...'9', '-', '_' => try writer.writeByte(byte),
            '.' => if (mode == .text) try writer.writeByte(byte) else try writer.writeAll("\\x2e"),
            else => try writer.print("\\x{x:0>2}", .{byte}),
        }
    }
}

fn upstreamFields(writer: *std.Io.Writer, upstream: *const Upstream) std.Io.Writer.Error!void {
    try writer.print(" upstream={f} upstream_proto={s}", .{
        upstream.address,
        @tagName(upstream.protocol),
    });
    if (upstream.tls_name) |name| {
        try writer.writeAll(" tls_name=\"");
        // Configuration limits this field to 253 bytes. Preserve the line bound for custom callers.
        try escaped(writer, name[0..@min(name.len, 253)], .text);
        try writer.writeByte('"');
    }
}

pub fn failure(logger: *Logger, io: std.Io, upstream: *const Upstream, reason: []const u8) void {
    var writer: std.Io.Writer = .fixed(&logger.buffer);
    timestamp(&writer, std.Io.Timestamp.now(io, .real).toMilliseconds()) catch return;
    writer.writeAll(" event=upstream_failure") catch return;
    upstreamFields(&writer, upstream) catch return;
    writer.writeAll(" reason=\"") catch return;
    escaped(&writer, reason[0..@min(reason.len, 128)], .text) catch return;
    writer.writeAll("\"\n") catch return;
    logger.sink.write(io, logger.sink.context, writer.buffered()) catch return;
}

pub fn health(
    logger: *Logger,
    io: std.Io,
    upstream: *const Upstream,
    state: enum { down, restored },
    failures: u32,
) void {
    var writer: std.Io.Writer = .fixed(&logger.buffer);
    timestamp(&writer, std.Io.Timestamp.now(io, .real).toMilliseconds()) catch return;
    writer.writeAll(" event=upstream_health") catch return;
    upstreamFields(&writer, upstream) catch return;
    writer.print(" state={s} failures={d}\n", .{ @tagName(state), failures }) catch return;
    logger.sink.write(io, logger.sink.context, writer.buffered()) catch return;
}

fn timestamp(writer: *std.Io.Writer, unix_ms: i64) std.Io.Writer.Error!void {
    if (unix_ms < 0) return writer.writeAll("timestamp=unknown");
    if (unix_ms > 253402300799999) return writer.writeAll("timestamp=unknown");
    const seconds: std.time.epoch.EpochSeconds = .{ .secs = @intCast(@divFloor(unix_ms, 1000)) };
    const day = seconds.getEpochDay();
    const year = day.calculateYearDay();
    const month = year.calculateMonthDay();
    const clock = seconds.getDaySeconds();
    try writer.print("{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}Z", .{
        year.year,
        @intFromEnum(month.month),
        month.day_index + 1,
        clock.getHoursIntoDay(),
        clock.getMinutesIntoHour(),
        clock.getSecondsIntoMinute(),
        @as(u16, @intCast(@mod(unix_ms, 1000))),
    });
}
