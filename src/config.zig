const std = @import("std");
const names = @import("wire/name.zig");
const validation = @import("config/validation.zig");

pub const Name = names.Name;
pub const Endpoint = @import("config/endpoint.zig").Endpoint;

pub const default_path = "/etc/z53/z53.zon";
pub const source_bytes_max = 65536;
pub const workspace_bytes_max = 4 * 1024 * 1024;
pub const zones_max = 64;
pub const listeners_max = 16;
pub const upstreams_max = 16;
pub const cache_capacity_max = 100000;
pub const cache_entries_max = 1000000;
pub const Error = error{InvalidConfig};
pub const QueryType = union(enum(u16)) {
    number: u16 = 0,
    A: void = 1,
    NS: void = 2,
    CNAME: void = 5,
    SOA: void = 6,
    PTR: void = 12,
    MX: void = 15,
    TXT: void = 16,
    AAAA: void = 28,
    SRV: void = 33,
    NAPTR: void = 35,
    DS: void = 43,
    RRSIG: void = 46,
    NSEC: void = 47,
    DNSKEY: void = 48,
    NSEC3: void = 50,
    TLSA: void = 52,
    SVCB: void = 64,
    HTTPS: void = 65,
    ANY: void = 255,

    pub fn code(self: QueryType) u16 {
        return switch (self) {
            .number => |number| number,
            else => @intFromEnum(self),
        };
    }
};
pub const Hosts = struct {
    path: []const u8 = "/etc/hosts",
    ttl: u32 = 30,
    reload_s: u32 = 5,
};
pub const Tls = struct { server_name: []const u8 };
pub const Upstream = struct {
    address: []const u8,
    tls: ?Tls = null,
    // These independent schema switches preserve the reference ZON syntax.
    force_tcp: bool = false,

    pub fn endpoint(self: *const Upstream, target: *Endpoint) void {
        target.parse(self.address, if (self.tls != null) 853 else 53) catch unreachable;
    }
};
pub const Cache = struct {
    max_ttl_s: u32 = 3600,
    min_ttl_s: u32 = 5,
    neg_max_ttl_s: u32 = 1800,
    capacity: u32 = 10000,

    pub fn denialMaximum(self: *const Cache) u32 {
        return @min(self.max_ttl_s, self.neg_max_ttl_s);
    }
};
pub const Zone = struct {
    suffix: []const u8,
    hosts: ?Hosts = null,
    nodata: []const QueryType = &.{},
    upstreams: []const Upstream,
    max_fails: u32 = 2,
    health_check_interval_s: f64 = 0.5,
    read_timeout_s: f64 = 2,
    conn_expire_s: f64 = 10,
    cache: ?Cache = .{},
    serve_stale_s: u32 = 0,
    rotate: bool = false,
};
pub const Config = struct {
    listen: []const []const u8 = &.{"127.0.0.1:53"},
    zones: []Zone,
};

pub const Diagnostic = struct {
    path: []const u8,
    line: u32 = 1,
    column: u32 = 1,
    reason: [512]u8 = undefined,
    length: u16 = 0,

    pub fn message(self: *const Diagnostic) []const u8 {
        return self.reason[0..self.length];
    }

    pub fn set(self: *Diagnostic, reason: []const u8) Error {
        self.length = @intCast(@min(reason.len, self.reason.len));
        @memcpy(self.reason[0..self.length], reason[0..self.length]);
        return error.InvalidConfig;
    }

    pub fn position(self: *Diagnostic, source: []const u8, offset: usize) void {
        self.line = 1;
        self.column = 1;
        for (source[0..offset]) |byte| {
            if (byte == '\n') {
                self.line += 1;
                self.column = 1;
            } else self.column += 1;
        }
    }

    pub fn format(self: *const Diagnostic, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print("{s}:{d}:{d}: error: {s}\n", .{
            self.path, self.line, self.column, self.message(),
        });
    }
};

/// Parsed storage borrows workspace; reusing it invalidates the previous Config.
/// Source and workspace must not overlap. Source is borrowed only during this call.
/// Diagnostic owns its reason and borrows its path. Failure invalidates target.
pub fn parse(
    target: *Config,
    source: [:0]const u8,
    workspace: []u8,
    diagnostic: *Diagnostic,
) Error!void {
    errdefer target.* = undefined;
    diagnostic.line = 1;
    diagnostic.column = 1;
    diagnostic.length = 0;
    try preflight(source, diagnostic);
    const memory = workspace[0..@min(workspace.len, workspace_bytes_max)];
    var fixed = std.heap.FixedBufferAllocator.init(memory);
    const allocator = fixed.allocator();
    var diagnostics: std.zon.parse.Diagnostics = .{};
    target.* = std.zon.parse.fromSliceAlloc(
        Config,
        allocator,
        source,
        &diagnostics,
        .{},
    ) catch |err| {
        if (err == error.OutOfMemory) return diagnostic.set("configuration workspace exhausted");
        var errors = diagnostics.iterateErrors();
        if (errors.next()) |failure| {
            const location = failure.getLocation(&diagnostics);
            diagnostic.line = @intCast(location.line + 1);
            diagnostic.column = @intCast(location.column + 1);
            var writer: std.Io.Writer = .fixed(&diagnostic.reason);
            writer.print("{f}", .{failure.fmtMessage(&diagnostics)}) catch {
                // The fixed diagnostic retains the available prefix of an oversized message.
                std.debug.assert(writer.end <= diagnostic.reason.len);
            };
            diagnostic.length = @intCast(writer.end);
        }
        return error.InvalidConfig;
    };
    var context: validation.Context = .{ .diagnostics = &diagnostics, .diagnostic = diagnostic };
    try context.validate(allocator, target);
}

/// Caller provides source_bytes_max + 2 bytes for the oversize check and sentinel.
pub fn load(
    target: *Config,
    io: std.Io,
    source_buffer: []u8,
    workspace: []u8,
    diagnostic: *Diagnostic,
) Error!void {
    std.debug.assert(source_buffer.len >= source_bytes_max + 2);
    diagnostic.line = 1;
    diagnostic.column = 1;
    const source = std.Io.Dir.cwd().readFile(
        io,
        diagnostic.path,
        source_buffer[0 .. source_bytes_max + 1],
    ) catch |err| {
        return diagnostic.set(@errorName(err));
    };
    source_buffer[source.len] = 0;
    try parse(target, source_buffer[0..source.len :0], workspace, diagnostic);
}

fn preflight(source: [:0]const u8, diagnostic: *Diagnostic) Error!void {
    if (source.len > source_bytes_max) {
        diagnostic.position(source, source_bytes_max);
        return diagnostic.set("configuration exceeds 65536 bytes");
    }
    var tokenizer = std.zig.Tokenizer.init(source);
    var depth: u16 = 0;
    var tokens: u32 = 0;
    var previous: std.zig.Token.Tag = .eof;
    while (tokens < 8192) : (tokens += 1) {
        const token = tokenizer.next();
        switch (token.tag) {
            .eof => return,
            .l_brace, .l_bracket, .l_paren => {
                depth += 1;
                if (depth > 16) {
                    diagnostic.position(source, token.loc.start);
                    return diagnostic.set("configuration nesting exceeds 16");
                }
            },
            .r_brace, .r_bracket, .r_paren => depth -|= 1,
            .minus => {
                if (previous == .minus) {
                    diagnostic.position(source, token.loc.start);
                    return diagnostic.set("repeated negation is not valid ZON");
                }
            },
            .period,
            .comma,
            .equal,
            .identifier,
            .string_literal,
            .multiline_string_literal_line,
            .char_literal,
            .number_literal,
            => {},
            else => {
                // std's AST parser also accepts Zig; exclude its recursive prefix grammar.
                diagnostic.position(source, token.loc.start);
                return diagnostic.set("token is not valid in ZON");
            },
        }
        previous = token.tag;
    }
    const extra = tokenizer.next();
    if (extra.tag == .eof) return;
    diagnostic.position(source, extra.loc.start);
    return diagnostic.set("configuration exceeds 8192 tokens");
}

/// Query names retain wire label framing, including literal dots inside labels.
/// Routing does not allocate and returns null when the resolver must answer REFUSED.
pub fn route(config: *const Config, name: *const names.Name) ?u16 {
    name.validate() catch return null;
    var selected: ?u16 = null;
    var length: usize = 0;
    for (config.zones, 0..) |*zone, index| {
        if (zone.suffix.len <= length) continue;
        var suffix: names.Name = .{};
        suffix.fromText(zone.suffix) catch unreachable;
        if (matches(name, &suffix)) {
            selected = @intCast(index);
            length = zone.suffix.len;
        }
    }
    return selected;
}

fn matches(name: *const names.Name, suffix: *const names.Name) bool {
    var offset: usize = 0;
    while (offset < name.length) {
        if (std.ascii.eqlIgnoreCase(name.wire()[offset..], suffix.wire())) return true;
        offset += @as(usize, name.bytes[offset]) + 1;
    }
    return false;
}

/// The slice excludes argv[0]. Reject ambiguous or repeated overrides.
pub fn configPath(arguments: []const []const u8) error{InvalidArguments}![]const u8 {
    if (arguments.len == 0) return default_path;
    if (arguments.len != 2) return error.InvalidArguments;
    if (!std.mem.eql(u8, arguments[0], "-c")) return error.InvalidArguments;
    if (arguments[1].len == 0) return error.InvalidArguments;
    return arguments[1];
}
