//! #1: caller-owned TLS records survive the same retirement barriers as DNS buffers.
const std = @import("std");
const Io = std.Io;
const assert = std.debug.assert;

pub const engine = @import("ztls");

pub const Error = error{ TransportFailure, LocalFailure };
pub const TrustError = error{ TrustStoreTooLarge, TrustStoreLoadFailed };

pub const Trust = struct {
    bundle: std.crypto.Certificate.Bundle,
    storage: [1536 * 1024]u8,

    pub fn init(self: *Trust, io: Io) TrustError!void {
        self.bundle = .empty;
        var allocator: std.heap.FixedBufferAllocator = .init(&self.storage);
        self.bundle.rescan(allocator.allocator(), io, Io.Timestamp.now(io, .real)) catch |err| {
            self.bundle = .empty;
            return switch (err) {
                error.OutOfMemory => error.TrustStoreTooLarge,
                else => error.TrustStoreLoadFailed,
            };
        };
        if (self.bundle.map.count() == 0) return error.TrustStoreLoadFailed;
    }
};

pub const Connection = struct {
    handshake: ?engine.ClientHandshake = null,
    records: engine.RecordBuffer,
    reassembly: [65536]u8,
    record_storage: [33290]u8,
    output: [16645]u8,
    write_offset: u32 = 0,
    write_length: u32 = 0,
    query_offset: u32 = 0,
    query_length: u32 = 0,
    phase: enum { request, response } = .request,
    plaintext: []const u8 = &.{},
    failure_reason: ?[]const u8 = null,

    pub const Action = union(enum) {
        read,
        write,
        data: []const u8,
        request_sent,
    };

    pub fn init(self: *Connection, io: Io, name: []const u8, trust: *const Trust) Error!void {
        assert(self.handshake == null);
        self.failure_reason = null;
        var entropy: [96]u8 = undefined;
        defer std.crypto.secureZero(u8, &entropy);
        io.randomSecure(&entropy) catch return error.LocalFailure;
        var x25519 = engine.x25519.KeyPair.generateDeterministic(.init(entropy[0..32].*)) catch
            return error.LocalFailure;
        defer x25519.secureZero();
        var p256 = engine.p256.KeyPair.generateDeterministic(.init(entropy[32..64].*)) catch
            return error.LocalFailure;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&p256));
        self.handshake = .init(.{
            .keypairs = .initWithP256(x25519, p256),
            .host_name = name,
            .now_sec = Io.Timestamp.now(io, .real).toSeconds(),
            .random = .init(entropy[64..96].*),
            .bundle = &trust.bundle,
            .reassembly = &self.reassembly,
        });
        errdefer self.deinit();
        self.records = .init(&self.record_storage);
        self.plaintext = &.{};
        self.queue(self.handshake.?.start(&self.output) catch return error.LocalFailure);
    }

    // ziglint-ignore: Z030 -- The vacant sentinel permits session reuse after secret erasure.
    pub fn deinit(self: *Connection) void {
        if (self.handshake) |*handshake| handshake.deinit();
        self.handshake = null;
        std.crypto.secureZero(u8, &self.reassembly);
        std.crypto.secureZero(u8, &self.record_storage);
        std.crypto.secureZero(u8, &self.output);
        self.* = undefined;
        self.handshake = null;
        self.failure_reason = null;
    }

    pub fn begin(self: *Connection, length: u32) void {
        self.failure_reason = null;
        self.query_offset = 0;
        self.query_length = length;
        self.phase = .request;
    }

    fn queue(self: *Connection, bytes: []const u8) void {
        assert(bytes.ptr == &self.output);
        self.write_offset = 0;
        self.write_length = @intCast(bytes.len);
    }

    pub fn writable(self: *Connection) []u8 {
        return self.records.writable();
    }

    pub fn pending(self: *const Connection) []const u8 {
        return self.output[self.write_offset..self.write_length];
    }

    pub fn received(self: *Connection, count: i32) Error!void {
        if (count <= 0) return error.TransportFailure;
        if (@as(u32, @intCast(count)) > self.records.storage.len - self.records.filled)
            return error.TransportFailure;
        self.records.advance(@intCast(count));
    }

    pub fn sent(self: *Connection, count: i32) Error!void {
        if (count <= 0) return error.TransportFailure;
        if (@as(u32, @intCast(count)) > self.write_length - self.write_offset)
            return error.TransportFailure;
        self.write_offset += @intCast(count);
        if (self.write_offset == self.write_length) self.handshake.?.completeWrite();
    }

    fn failed(self: *Connection, err: engine.errors.HandshakeError) Error {
        // Error names are static diagnostics, never certificate bytes or session secrets.
        self.failure_reason = @errorName(err);
        return classify(err);
    }

    pub fn next(self: *Connection, query: []const u8) Error!Action {
        for (0..4096) |_| {
            // Finished can install application keys before its bytes reach the socket.
            if (self.write_offset < self.write_length) return .write;
            if (self.phase == .request) {
                if (self.handshake.?.isConnected()) {
                    if (self.query_offset == self.query_length) {
                        self.phase = .response;
                        return .request_sent;
                    }
                    const end = @min(self.query_offset + 16384, self.query_length);
                    self.queue(self.handshake.?.sendApplicationData(
                        query[self.query_offset..end],
                        &self.output,
                    ) catch |err| return self.failed(err));
                    self.query_offset = end;
                    return .write;
                }
            }
            if (self.plaintext.len > 0) return .{ .data = self.plaintext };
            const record = self.records.next() catch return error.TransportFailure;
            const event = self.handshake.?.handleRecord(
                record orelse return .read,
                &self.output,
            ) catch |err| return self.failed(err);
            switch (event) {
                .write => |bytes| self.queue(bytes),
                .key_update => |update| if (update.response) |bytes| self.queue(bytes),
                .application_data => |bytes| self.plaintext = bytes,
                .closed => return error.TransportFailure,
                .none, .new_session_ticket => {},
            }
        }
        return error.TransportFailure;
    }
};

pub fn classify(err: engine.errors.HandshakeError) Error {
    return switch (engine.errors.classify(err)) {
        .internal, .buffer, .options => error.LocalFailure,
        else => error.TransportFailure,
    };
}
