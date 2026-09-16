//! Bounded completion logs. Sink failures never change DNS outcomes.
//! The runtime queues lines and delivers them through the event loop.
const std = @import("std");
const system = std.c;
const Io = std.Io;
const IpAddress = Io.net.IpAddress;
const mem = std.mem;
const assert = std.debug.assert;

const resolver = @import("../resolver.zig");
const FailureReason = @import("failure.zig").Reason;
const wire = resolver.wire;

const failure_reason_bytes_max = 128;

pub const line_bytes_max = 3072;
/// SPEC §4: the delivery queue holds this many formatted lines.
pub const queue_slots_max = 64;
const queue_mask = queue_slots_max - 1;
pub const Protocol = enum { udp, tcp, dot };
pub const Query = struct {
    client: ?IpAddress,
    protocol: Protocol,
    started_ns: u64,
};
pub const Upstream = struct {
    address: IpAddress,
    protocol: Protocol,
    tls_name: ?[]const u8 = null,
};
pub const Sink = struct {
    context: ?*anyopaque = null,
    write: *const fn (Io, ?*anyopaque, []const u8) error{WriteFailed}!void = stderr,

    fn stderr(io: Io, _: ?*anyopaque, bytes: []const u8) error{WriteFailed}!void {
        // One bounded write avoids retry loops. A short write loses the remainder.
        _ = Io.File.stderr().writeStreaming(io, &.{}, &.{bytes}, 1) catch
            return error.WriteFailed;
    }
};

/// One formatted line. The length precedes the content, so the queue needs
/// no separate boundary structure.
const Slot = struct {
    length: u32,
    bytes: [line_bytes_max]u8,
};

/// The event thread owns this workspace. Each synchronous sink call consumes its borrowed bytes.
/// Sink callbacks must not call logging functions on the same logger.
pub const Logger = struct {
    sink: Sink = .{},
    buffer: [line_bytes_max]u8 = undefined,

    /// Fixed delivery queue, owned by the event thread. The counters are
    /// monotonic, so full and empty are subtractions that never wrap.
    queue: [queue_slots_max]Slot = undefined,
    enqueued: u64 = 0,
    delivered: u64 = 0,
    write_state: enum { idle, poll, executing } = .idle,
    /// Content bytes of the delivered line already accepted by the sink file.
    write_offset: u32 = 0,

    /// The runtime installs this sink so formatted lines enter the queue
    /// instead of the dispatch path. The runtime then drives the writes.
    pub fn queueSink(self: *Logger) Sink {
        return .{ .context = self, .write = enqueueLine };
    }

    fn slot(self: *Logger, counter: u64) *Slot {
        return &self.queue[@as(usize, @truncate(counter)) & queue_mask];
    }

    /// Copies one formatted line into the queue. SPEC §4: a full queue
    /// discards the oldest undelivered line first. The kernel owns the
    /// executing line, so a full queue behind it discards the incoming line.
    pub fn enqueue(self: *Logger, line: []const u8) void {
        assert(line.len <= line_bytes_max);
        if (self.enqueued - self.delivered == queue_slots_max) {
            if (self.write_state == .executing) return;
            self.delivered += 1;
            self.write_offset = 0;
        }
        const target = self.slot(self.enqueued);
        @memcpy(target.bytes[0..line.len], line);
        target.length = @intCast(line.len);
        self.enqueued += 1;
    }

    /// Returns the next sink slice and marks it in flight, or null when a
    /// write or poll is outstanding or the queue is empty.
    pub fn beginWrite(self: *Logger) ?[]const u8 {
        if (self.write_state != .idle) return null;
        if (self.delivered == self.enqueued) return null;
        self.write_state = .executing;
        return self.remaining();
    }

    fn remaining(self: *Logger) []const u8 {
        const current = self.slot(self.delivered);
        assert(self.write_offset < current.length);
        return current.bytes[self.write_offset..current.length];
    }

    /// Accepts `count` bytes written by the sink file. A partial count
    /// leaves the remainder queued for the next submission.
    pub fn writeAdvanced(self: *Logger, count: usize) void {
        assert(self.write_state == .executing);
        assert(count <= self.remaining().len);
        self.write_offset += @intCast(count);
        if (self.write_offset == self.slot(self.delivered).length) {
            self.delivered += 1;
            self.write_offset = 0;
        }
        self.write_state = .idle;
    }

    /// The sink file accepted nothing and is not writable. The caller arms a
    /// writability poll and calls pollReady when it fires.
    pub fn writeStalled(self: *Logger) void {
        assert(self.write_state == .executing);
        self.write_state = .poll;
    }

    pub fn pollReady(self: *Logger) void {
        assert(self.write_state == .poll);
        self.write_state = .idle;
    }

    /// The sink file rejected the line. SPEC §4: discard it without a DNS error.
    pub fn writeFailed(self: *Logger) void {
        assert(self.write_state != .idle);
        self.delivered += 1;
        self.write_offset = 0;
        self.write_state = .idle;
    }

    /// No operation is outstanding. Teardown abandons the queued lines.
    pub fn writeCanceled(self: *Logger) void {
        assert(self.write_state != .idle);
        self.write_offset = 0;
        self.write_state = .idle;
    }
};

fn enqueueLine(_: Io, context: ?*anyopaque, line: []const u8) error{WriteFailed}!void {
    const logger: *Logger = @ptrCast(@alignCast(context.?));
    logger.enqueue(line);
}

pub fn peer(
    storage: *const system.sockaddr.storage,
    length: system.socklen_t,
) ?IpAddress {
    switch (storage.family) {
        system.AF.INET => {
            if (length != @sizeOf(system.sockaddr.in)) return null;
            const value: *const system.sockaddr.in = @ptrCast(storage);
            return .{ .ip4 = .{
                .bytes = @bitCast(value.addr),
                .port = mem.bigToNative(u16, value.port),
            } };
        },
        system.AF.INET6 => {
            if (length != @sizeOf(system.sockaddr.in6)) return null;
            const value: *const system.sockaddr.in6 = @ptrCast(storage);
            return .{ .ip6 = .{
                .bytes = value.addr,
                .port = mem.bigToNative(u16, value.port),
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
        .unix_ms = Io.Timestamp.now(io, .real).toMilliseconds(),
        .finished_ns = finished_ns,
    }) catch return;
    logger.sink.write(io, logger.sink.context, bytes) catch return;
}

pub const Time = struct {
    unix_ms: i64,
    finished_ns: u64,
};

pub fn format(
    buffer: *[line_bytes_max]u8,
    packet: *wire.Packet,
    query: *const Query,
    input: []const u8,
    answer: *const resolver.Answer,
    upstream: ?*const Upstream,
    time: Time,
) Io.Writer.Error![]const u8 {
    var writer: Io.Writer = .fixed(buffer);
    try timestamp(&writer, time.unix_ms);
    try writer.print(" event=query proto={s} client=", .{@tagName(query.protocol)});
    if (query.client) |client| {
        try writer.print("{f}", .{client});
    } else try writer.writeAll("unknown");
    try question(&writer, packet, input);
    try writer.writeAll(" rcode=");
    if (packet.parse(answer.bytes)) |_| {
        var rcode: u16 = @intFromEnum(packet.header.rcode());
        if (packet.opt) |index| {
            const extended: u16 = @intCast(packet.records[index].ttl_s >> wire.edns_rcode_shift);
            rcode |= extended << @bitSizeOf(wire.Rcode);
        }
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
    writer: *Io.Writer,
    packet: *wire.Packet,
    input: []const u8,
) Io.Writer.Error!void {
    packet.parse(input) catch return writer.writeAll(" qtype=unknown qname=unknown");
    if (packet.header.counts[0] != 1) return writer.writeAll(" qtype=unknown qname=unknown");
    var cursor: usize = wire.header_bytes;
    const value = packet.readQuestion(&cursor) catch
        return writer.writeAll(" qtype=unknown qname=unknown");
    var name: wire.Name = undefined;
    packet.name(&name, value.name) catch return writer.writeAll(" qtype=unknown qname=unknown");
    try writer.print(" qtype={d} qname=\"", .{@intFromEnum(value.kind)});
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
    writer: *Io.Writer,
    bytes: []const u8,
    mode: enum { label, text },
) Io.Writer.Error!void {
    for (bytes) |byte| {
        try switch (byte) {
            'a'...'z', 'A'...'Z', '0'...'9', '-', '_' => writer.writeByte(byte),
            '.' => if (mode == .text) writer.writeByte(byte) else writer.writeAll("\\x2e"),
            else => writer.print("\\x{x:0>2}", .{byte}),
        };
    }
}

fn upstreamFields(writer: *Io.Writer, upstream: *const Upstream) Io.Writer.Error!void {
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

pub fn failure(logger: *Logger, io: Io, upstream: *const Upstream, reason: FailureReason) void {
    var writer: Io.Writer = .fixed(&logger.buffer);
    timestamp(&writer, Io.Timestamp.now(io, .real).toMilliseconds()) catch return;
    writer.writeAll(" event=upstream_failure") catch return;
    upstreamFields(&writer, upstream) catch return;
    writer.writeAll(" reason=\"") catch return;
    const message = reason.message();
    escaped(&writer, message[0..@min(message.len, failure_reason_bytes_max)], .text) catch return;
    writer.writeAll("\"\n") catch return;
    logger.sink.write(io, logger.sink.context, writer.buffered()) catch return;
}

pub fn health(
    logger: *Logger,
    io: Io,
    upstream: *const Upstream,
    state: enum { down, restored },
    failures: u32,
) void {
    var writer: Io.Writer = .fixed(&logger.buffer);
    timestamp(&writer, Io.Timestamp.now(io, .real).toMilliseconds()) catch return;
    writer.writeAll(" event=upstream_health") catch return;
    upstreamFields(&writer, upstream) catch return;
    writer.print(" state={s} failures={d}\n", .{ @tagName(state), failures }) catch return;
    logger.sink.write(io, logger.sink.context, writer.buffered()) catch return;
}

fn timestamp(writer: *Io.Writer, unix_ms: i64) Io.Writer.Error!void {
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
