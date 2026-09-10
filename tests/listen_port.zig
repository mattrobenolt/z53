//! Stable loopback listener ports for the native socket tests.
//!
//! Every harness releases its reservation before the server binds the port.
//! A port drawn from the ephemeral range can be re-issued to any other host
//! process inside that window, and the server UDP bind then fails with
//! EADDRINUSE. UDP reuse is deliberately disabled so a leaked listener socket
//! still fails the bind.
//! Candidates outside the ephemeral range are never automatically re-issued,
//! so probing there closes the race without weakening the restart assertions.
//! The above-range span is preferred: services conventionally live below the
//! range. Within each span, processes walk disjoint stride classes by pid, so
//! concurrently running suites never probe one another's candidates.

const std = @import("std");
const builtin = @import("builtin");
const runtime = @import("runtime");

const Address = runtime.address.Address;

pub const Error = error{ NoFreePort, SocketFailed, ListenFailed };

const Range = struct { low: u16, high: u16 };

/// Concurrent suites probe disjoint candidates while their pids differ modulo
/// the stride; the above-range span still holds 141 ports per class.
const stride = 32;
const reservations_max = 512;
const low_water: u32 = 1025; // Skip privileged ports.
const buffer_bytes = 64;

var range_cache: ?Range = null;
var reserved: [reservations_max]u16 = undefined;
var reserved_count: u16 = 0;

/// Reserve a loopback port that concurrent ephemeral allocation cannot take.
/// The address retains the chosen port; the caller still rebinds it later.
pub fn reserve(address: *Address, host: []const u8) Error!u16 {
    const current = ephemeralRange();
    for (spans(current)) |span| {
        if (try scan(span, address, host)) |port| return port;
    }
    return error.NoFreePort;
}

const Span = struct {
    first: u32,
    last: u32,
    direction: enum { ascending, descending },
};

/// The span above the range comes first: services conventionally live below
/// it. The below-range span exists for Darwin, whose default range ends at
/// 65535 and leaves nothing above.
fn spans(range: Range) [2]Span {
    return .{
        .{ .first = @as(u32, range.high) + 1, .last = 65535, .direction = .ascending },
        .{ .first = low_water, .last = @as(u32, range.low) -| 1, .direction = .descending },
    };
}

/// Walk this process's stride class within the span, probing candidates until
/// one binds or the class is exhausted.
fn scan(
    span: Span,
    address: *Address,
    host: []const u8,
) Error!?u16 {
    if (span.first > span.last) return null;
    const width: u32 = span.last - span.first + 1;
    const class: u32 = @as(u32, @intCast(std.c.getpid())) % stride;
    if (class >= width) return null;
    const capacity: u32 = 1 + (width - 1 - class) / stride;
    for (0..capacity) |walk| {
        const offset: u32 = class + stride * @as(u32, @intCast(walk));
        const candidate: u16 = switch (span.direction) {
            .ascending => @intCast(span.first + offset),
            .descending => @intCast(span.last - offset),
        };
        if (remembered(candidate)) continue;
        if (try probe(address, host, candidate)) return candidate;
    }
    return null;
}

/// The candidate is viable only when a fresh UDP and TCP bind both succeed.
fn probe(address: *Address, host: []const u8, candidate: u16) Error!bool {
    // Host is a call-site literal; a parse failure is a programming error.
    const ip = std.Io.net.IpAddress.parse(host, candidate) catch unreachable;
    address.fromIp(&ip);
    const datagram = address.bind(std.c.SOCK.DGRAM) catch |err| switch (err) {
        error.BindFailed => return false,
        error.UnresolvedListener => unreachable, // bind never resolves.
        else => |rest| return rest,
    };
    _ = std.c.close(datagram);
    const stream = address.bind(std.c.SOCK.STREAM) catch |err| switch (err) {
        error.BindFailed => return false,
        error.UnresolvedListener => unreachable, // bind never resolves.
        else => |rest| return rest,
    };
    _ = std.c.close(stream);
    if (reserved_count == reservations_max) return error.NoFreePort;
    reserved[reserved_count] = candidate;
    reserved_count += 1;
    return true;
}

fn outside(range: Range, port: u16) bool {
    if (port < range.low) return true;
    return port > range.high;
}

fn remembered(candidate: u16) bool {
    for (reserved[0..reserved_count]) |port| {
        if (port == candidate) return true;
    }
    return false;
}

fn ephemeralRange() Range {
    if (range_cache) |cached| return cached;
    const discovered = switch (builtin.os.tag) {
        .linux => linuxRange(),
        .macos => darwinRange(),
        else => unreachable, // The supported targets are Linux and Darwin.
    };
    range_cache = discovered;
    return discovered;
}

fn linuxRange() Range {
    const linux = std.os.linux;
    const descriptor = linux.open("/proc/sys/net/ipv4/ip_local_port_range", .{}, 0);
    if (linux.errno(descriptor) != .SUCCESS) return linuxDefault();
    defer _ = linux.close(@intCast(descriptor));
    var buffer: [buffer_bytes]u8 = undefined;
    const read = linux.read(@intCast(descriptor), &buffer, buffer.len);
    if (linux.errno(read) != .SUCCESS) return linuxDefault();
    return parseRange(buffer[0..read]) orelse linuxDefault();
}

fn linuxDefault() Range {
    return .{ .low = 32768, .high = 60999 };
}

fn parseRange(bytes: []const u8) ?Range {
    var numbers: [2]u16 = .{ 0, 0 };
    var count: usize = 0;
    var value: u32 = 0;
    var digits: usize = 0;
    for (bytes) |byte| {
        if (byte >= '0') {
            if (byte <= '9') {
                value = value * 10 + (byte - '0');
                if (value > 65535) return null;
                digits += 1;
                continue;
            }
        }
        if (digits > 0) {
            if (count == 2) return null;
            numbers[count] = @intCast(value);
            count += 1;
            value = 0;
            digits = 0;
        }
    }
    if (digits > 0) {
        if (count < 2) {
            numbers[count] = @intCast(value);
            count += 1;
        }
    }
    if (count != 2) return null;
    if (numbers[0] == 0) return null;
    if (numbers[1] < numbers[0]) return null;
    return .{ .low = numbers[0], .high = numbers[1] };
}

fn darwinRange() Range {
    const fallback: Range = .{ .low = 49152, .high = 65535 };
    var low: c_int = fallback.low;
    var high: c_int = fallback.high;
    readPortrange("net.inet.ip.portrange.first", &low);
    readPortrange("net.inet.ip.portrange.last", &high);
    if (low < 1) return fallback;
    if (high > 65535) return fallback;
    if (high < low) return fallback;
    return .{ .low = @intCast(low), .high = @intCast(high) };
}

fn readPortrange(name: [*:0]const u8, value: *c_int) void {
    var length: usize = @sizeOf(c_int);
    // A failed query keeps the caller's default value.
    _ = std.c.sysctlbyname(name, value, &length, null, 0);
}

test "range parser accepts the proc format" {
    const parsed = parseRange("32768\t60999\n").?;
    try std.testing.expectEqual(@as(u16, 32768), parsed.low);
    try std.testing.expectEqual(@as(u16, 60999), parsed.high);
}

test "range parser rejects malformed input" {
    try std.testing.expectEqual(@as(?Range, null), parseRange("60999 32768\n"));
    try std.testing.expectEqual(@as(?Range, null), parseRange("0 60999\n"));
    try std.testing.expectEqual(@as(?Range, null), parseRange("32768\n"));
    try std.testing.expectEqual(@as(?Range, null), parseRange("99999 100000\n"));
    try std.testing.expectEqual(@as(?Range, null), parseRange(""));
}

test "spans prefer above the range and fall below it" {
    const linux_like = spans(.{ .low = 32768, .high = 60999 });
    try std.testing.expectEqual(@as(u32, 61000), linux_like[0].first);
    try std.testing.expectEqual(@as(u32, 65535), linux_like[0].last);
    try std.testing.expectEqual(.ascending, linux_like[0].direction);
    try std.testing.expectEqual(low_water, linux_like[1].first);
    try std.testing.expectEqual(@as(u32, 32767), linux_like[1].last);
    try std.testing.expectEqual(.descending, linux_like[1].direction);
    // A range ending at 65535 leaves an empty above span; the below span answers.
    const darwin_like = spans(.{ .low = 49152, .high = 65535 });
    try std.testing.expect(darwin_like[0].first > darwin_like[0].last);
    try std.testing.expect(darwin_like[1].first <= darwin_like[1].last);
    var address: Address = undefined;
    const port = try scan(darwin_like[1], &address, "127.0.0.1") orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(port >= low_water);
    try std.testing.expect(port <= 49151);
}

test "reserve hands out distinct ports outside the ephemeral range" {
    var first: Address = undefined;
    var second: Address = undefined;
    const first_port = try reserve(&first, "127.0.0.1");
    const second_port = try reserve(&second, "127.0.0.1");
    try std.testing.expect(first_port != second_port);
    const current = ephemeralRange();
    try std.testing.expect(outside(current, first_port));
    try std.testing.expect(outside(current, second_port));
    // The reserved ports accept fresh UDP and TCP binds after the probe closed.
    const datagram = try first.bind(std.c.SOCK.DGRAM);
    _ = std.c.close(datagram);
    const stream = try second.bind(std.c.SOCK.STREAM);
    _ = std.c.close(stream);
}
