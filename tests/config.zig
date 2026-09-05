const std = @import("std");
const config = @import("config");
const expect = std.testing.expect;
const equal = std.testing.expectEqual;
const strings = std.testing.expectEqualStrings;
const upstream = ".{ .address = \"127.0.0.1:1053\" }";
const zone_start = ".{ .zones = .{ .{ .suffix = \".\", .upstreams = .{" ++ upstream ++ "}, ";
const zone_end = " } } }";
const minimal = ".{ .zones = .{ .{ .suffix = \".\", .upstreams = .{" ++ upstream ++ "} } } }";

const Harness = struct {
    workspace: []u8,
    parsed: config.Config = undefined,
    diagnostic: config.Diagnostic = .{ .path = "test.zon" },

    fn init(self: *Harness) !void {
        self.* = .{ .workspace = try std.testing.allocator.alloc(u8, config.workspace_bytes_max) };
    }

    fn deinit(self: *Harness) void {
        std.testing.allocator.free(self.workspace);
        self.* = undefined;
    }

    fn parse(self: *Harness, source: [:0]const u8) config.Error!void {
        try config.parse(&self.parsed, source, self.workspace, &self.diagnostic);
    }

    fn rejects(self: *Harness, source: [:0]const u8, reason: []const u8) !void {
        try std.testing.expectError(error.InvalidConfig, self.parse(source));
        if (std.mem.indexOf(u8, self.diagnostic.message(), reason) == null) {
            std.debug.print("expected reason containing '{s}', got: {f}", .{
                reason, &self.diagnostic,
            });
            return error.TestUnexpectedResult;
        }
        try expect(self.diagnostic.line > 0);
        try expect(self.diagnostic.column > 0);
    }
};

// SPEC §5 and §7: omitted settings retain every reference default.
test "typed configuration defaults" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    try harness.parse(minimal);
    try strings("127.0.0.1:53", harness.parsed.listen[0]);
    const zone = &harness.parsed.zones[0];
    try strings(".", zone.suffix);
    try equal(null, zone.hosts);
    try equal(0, zone.nodata.len);
    try equal(2, zone.max_fails);
    try equal(0.5, zone.health_check_interval_s);
    try equal(2, zone.read_timeout_s);
    try equal(10, zone.conn_expire_s);
    try equal(0, zone.serve_stale_s);
    try equal(false, zone.rotate);
    try equal(false, zone.upstreams[0].force_tcp);
    try equal(null, zone.upstreams[0].tls);
    try std.testing.expectEqualDeep(config.Cache{}, zone.cache.?);
}

// SPEC §6: parse actual shipped files, preserving the deployment differences.
test "both reference configuration files parse and validate" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var source: [config.source_bytes_max + 2]u8 = undefined;
    const paths = [_][]const u8{ "examples/launchpad.zon", "examples/darwin.zon" };
    for (paths, 0..) |path, index| {
        harness.diagnostic.path = path;
        try config.load(
            &harness.parsed,
            std.testing.io,
            &source,
            harness.workspace,
            &harness.diagnostic,
        );
        try equal(@as(usize, 2) + index, harness.parsed.zones.len);
        try strings("127.0.0.1:53", harness.parsed.listen[0]);
        const root = &harness.parsed.zones[0];
        try strings(".", root.suffix);
        try strings(
            if (index == 0) "169.254.169.253:53" else "192.168.2.100:53",
            root.upstreams[0].address,
        );
        try equal(3, root.upstreams.len);
        try strings("1.1.1.1:853", root.upstreams[1].address);
        try strings("1.0.0.1:853", root.upstreams[2].address);
        for (root.upstreams[1..]) |*item| {
            try strings("one.one.one.one", item.tls.?.server_name);
            var endpoint: config.Endpoint = undefined;
            item.endpoint(&endpoint);
            try equal(853, endpoint.port);
        }
        try std.testing.expectEqualDeep(config.Hosts{}, root.hosts.?);
        try equal(28, root.nodata[0].code());
        try equal(1, root.nodata.len);
        try equal(1, root.max_fails);
        try equal(5, root.health_check_interval_s);
        try equal(true, root.rotate);
        const tailscale = &harness.parsed.zones[1];
        try strings("ts.net.", tailscale.suffix);
        try strings("100.100.100.100:53", tailscale.upstreams[0].address);
        try equal(1, tailscale.upstreams.len);
        try equal(0, tailscale.nodata.len);
        try equal(@as(u32, 1) + @as(u32, @intCast(index)), tailscale.max_fails);
        try equal(30, tailscale.cache.?.max_ttl_s);
        try equal(30, tailscale.cache.?.denialMaximum());
        try std.testing.expectEqualDeep(config.Hosts{}, tailscale.hosts.?);
        if (index == 1) {
            const cluster = &harness.parsed.zones[2];
            try strings("svc.cluster.local.", cluster.suffix);
            try strings("192.168.194.138:53", cluster.upstreams[0].address);
            try equal(true, cluster.upstreams[0].force_tcp);
            try equal(60, cluster.health_check_interval_s);
            try equal(true, cluster.rotate);
        }
    }
}

// SPEC §5: optional hosts/cache settings and TLS default port remain expressible.
test "explicit optional settings and transport ports" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    try harness.parse(
        \\.{ .zones = .{ .{
        \\ .suffix = "Ts.NET", .hosts = .{ .path = "/tmp/hosts", .ttl = 42, .reload_s = 0 },
        \\ .cache = null, .serve_stale_s = 300, .max_fails = 0,
        \\ .upstreams = .{ .{
        \\  .address = "[::1]", .tls = .{ .server_name = "localhost" }, .force_tcp = true,
        \\ } },
        \\ .nodata = .{ .A, .AAAA, .{ .number = 65280 } },
        \\} } }
    );
    const zone = &harness.parsed.zones[0];
    try strings("ts.net.", zone.suffix);
    try equal(null, zone.cache);
    try equal(300, zone.serve_stale_s);
    try equal(0, zone.max_fails);
    try strings("/tmp/hosts", zone.hosts.?.path);
    try equal(42, zone.hosts.?.ttl);
    try equal(0, zone.hosts.?.reload_s);
    try equal(65280, zone.nodata[2].code());
    var endpoint: config.Endpoint = undefined;
    zone.upstreams[0].endpoint(&endpoint);
    try equal(853, endpoint.port);
    try strings("::1", endpoint.host);
    try endpoint.parse("localhost", 53);
    try equal(53, endpoint.port);
    try endpoint.parse("[::1]:1053", 53);
    try equal(1053, endpoint.port);
}

// SPEC §5: unknown fields and missing required fields fail typed std.zon parsing.
test "typed schema rejects unknown missing and mistyped fields" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const cases = .{
        .{ ".{ .zones = .{}, .typo = 1 }", "unexpected field" },
        .{ ".{}", "missing required field" },
        .{ ".{ .zones = .{ .{ .suffix = \".\" } } }", "missing required field" },
        .{ ".{ .zones = .{ .{ .upstreams = .{" ++ upstream ++ "} } } }", "missing required field" },
        .{
            ".{ .zones = .{ .{ .suffix = \".\", .upstreams = .{ .{} } } } }",
            "missing required field",
        },
        .{
            ".{ .zones = .{ .{ .suffix = \".\", .upstreams = .{ " ++
                ".{ .address = \"127.0.0.1\", .tls = .{} } } } } }",
            "missing required field",
        },
        .{ zone_start ++ ".rotate = 1" ++ zone_end, "expected type 'bool'" },
        .{ zone_start ++ ".cache = .{ .typo = 1 }" ++ zone_end, "unexpected field" },
        .{ zone_start ++ ".hosts = .{ .typo = 1 }" ++ zone_end, "unexpected field" },
        .{
            ".{ .zones = .{ .{ .suffix = \".\", .upstreams = .{ " ++
                ".{ .address = \"127.0.0.1\", " ++
                ".tls = .{ .server_name = \"localhost\", .typo = 1 } } } } } }",
            "unexpected field",
        },
        .{ ".{ .zones = ", "expected expression" },
    };
    inline for (cases) |case| try harness.rejects(case[0], case[1]);
}

// SPEC §5: every semantic validation rejects the offending configuration.
test "zone and TTL validation errors" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    try harness.rejects(
        ".{ .zones = .{ .{ .suffix = \".\", .upstreams = .{} } } }",
        "at least one upstream",
    );
    try harness.rejects(
        ".{ .zones = .{ .{ .suffix = \"Ts.NET\", .upstreams = .{" ++ upstream ++
            "} }, .{ .suffix = \"ts.net.\", .upstreams = .{" ++ upstream ++ "} } } }",
        "duplicate zone suffix",
    );
    const cases = .{
        .{ ".cache = .{ .min_ttl_s = 31, .max_ttl_s = 30 }", "min_ttl_s exceeds" },
        .{ ".cache = .{ .neg_max_ttl_s = 4 }", "denial maximum" },
        .{ ".cache = .{ .min_ttl_s = 0, .max_ttl_s = 4 }", "denial maximum" },
        .{ ".cache = .{ .capacity = 0 }", "capacity must be positive" },
        .{ ".cache = .{ .capacity = 100001 }", "exceeds 100000" },
        .{ ".read_timeout_s = nan", "finite" },
        .{ ".health_check_interval_s = inf", "finite" },
        .{ ".conn_expire_s = -1", "at least 0.001" },
        .{ ".read_timeout_s = 0", "at least 0.001" },
        .{ ".health_check_interval_s = 86401", "exceeds 86400" },
        .{ ".hosts = .{ .path = \"\" }", "must not be empty" },
        .{ ".hosts = .{ .path = \"a\\x00b\" }", "contains NUL" },
    };
    inline for (cases) |case| {
        try harness.rejects(zone_start ++ case[0] ++ zone_end, case[1]);
    }
    try harness.parse(zone_start ++
        ".cache = .{ .min_ttl_s = 5, .max_ttl_s = 5, .neg_max_ttl_s = 5 }" ++ zone_end);
    try equal(5, harness.parsed.zones[0].cache.?.denialMaximum());
}

// SPEC §4–5: semantic errors use actual AST positions, not searched text or line 1.
test "semantic and typed diagnostics report exact source positions" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    try harness.rejects(
        \\.{
        \\ .zones = .{
        \\  .{ .suffix = ".", // .upstreams = .{} is a decoy.
        \\     .upstreams = .{},
        \\  },
        \\ },
        \\}
    , "at least one upstream");
    try equal(4, harness.diagnostic.line);
    try equal(19, harness.diagnostic.column);
    try std.testing.expectFmt(
        "test.zon:4:19: error: zone requires at least one upstream\n",
        "{f}",
        .{&harness.diagnostic},
    );
    try harness.rejects(".{\n .zones = .{},\n .typo = 1,\n}", "unexpected field");
    try equal(3, harness.diagnostic.line);
    try equal(3, harness.diagnostic.column);
    try harness.rejects(
        ".{\n .zones = .{ .{ .suffix = \".\",\n .upstreams = .{ " ++
            ".{ .address = \"127.0.0.1\", .tls = .{} } } } } }",
        "server_name",
    );
    try equal(3, harness.diagnostic.line);
    try expect(harness.diagnostic.column > 40);
}

// SPEC §3.1, §5; RFC 1035 §2.3.4: longest case-insensitive label-boundary routing.
test "canonical suffix routing including binary label boundaries" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    try harness.parse(".{ .zones = .{ " ++
        ".{ .suffix = \"TS.NET\", .upstreams = .{" ++ upstream ++ "} }, " ++
        ".{ .suffix = \".\", .upstreams = .{" ++ upstream ++ "} }, " ++
        ".{ .suffix = \"deep.ts.net.\", .upstreams = .{" ++ upstream ++ "} } } }");
    try strings("ts.net.", harness.parsed.zones[0].suffix);
    var name: config.Name = .{};
    const cases = .{
        .{ "Ts.NeT.", 0 },   .{ "x.ts.net", 0 }, .{ "X.DEEP.TS.NET.", 2 },
        .{ "nots.net.", 1 }, .{ "xts.net.", 1 }, .{ "ts.net.evil.", 1 },
        .{ ".", 1 },
    };
    inline for (cases) |case| {
        try name.fromText(case[0]);
        try equal(@as(?u16, case[1]), config.route(&harness.parsed, &name));
    }
    name.length = 12;
    @memcpy(name.bytes[0..12], &[_]u8{ 6, 'x', '.', 'd', 'e', 'e', 'p', 2, 't', 's', 0, 0 });
    // Invalid wire names do not reach suffix matching.
    try equal(null, config.route(&harness.parsed, &name));
    name.length = 10;
    @memcpy(name.bytes[0..10], &[_]u8{ 8, 'x', '.', 't', 's', '.', 'n', 'e', 't', 0 });
    try equal(@as(?u16, 1), config.route(&harness.parsed, &name));
    harness.parsed.zones = harness.parsed.zones[0..1];
    try name.fromText("other.net.");
    try equal(null, config.route(&harness.parsed, &name));
}

// SPEC §1.7 and §5: startup path defaults and override have no socket dependency.
test "configuration path arguments" {
    try strings("/etc/z53/z53.zon", try config.configPath(&.{}));
    try strings("/tmp/test.zon", try config.configPath(&.{ "-c", "/tmp/test.zon" }));
    try std.testing.expectError(error.InvalidArguments, config.configPath(&.{"-c"}));
    try std.testing.expectError(error.InvalidArguments, config.configPath(&.{ "-c", "" }));
    try std.testing.expectError(
        error.InvalidArguments,
        config.configPath(&.{ "--config", "test.zon" }),
    );
    try std.testing.expectError(
        error.InvalidArguments,
        config.configPath(&.{ "-c", "a", "-c", "b" }),
    );
}

// SPEC §1.11 and §5: parser memory, source, token count and nesting are bounded.
test "configuration parser resource limits" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var bytes: [config.source_bytes_max + 2]u8 = @splat(' ');
    bytes[config.source_bytes_max + 1] = 0;
    try harness.rejects(bytes[0 .. config.source_bytes_max + 1 :0], "exceeds 65536 bytes");
    try equal(65537, harness.diagnostic.column);
    @memcpy(bytes[0..minimal.len], minimal);
    bytes[config.source_bytes_max] = 0;
    try harness.parse(bytes[0..config.source_bytes_max :0]);
    try std.testing.expectError(error.InvalidConfig, config.parse(
        &harness.parsed,
        minimal,
        &.{},
        &harness.diagnostic,
    ));
    try strings("configuration workspace exhausted", harness.diagnostic.message());
    try harness.rejects(".{" ** 17 ++ "}" ** 17, "nesting exceeds 16");
    try harness.rejects(" " ++ "0," ** 4097, "exceeds 8192 tokens");
    try harness.rejects("- " ** 8190 ++ "1", "repeated negation");
    try harness.rejects("!" ** 8190 ++ "true", "token is not valid in ZON");
}

fn listSource(
    buffer: []u8,
    prefix: []const u8,
    item: []const u8,
    count: u16,
    suffix: []const u8,
) ![:0]const u8 {
    var writer: std.Io.Writer = .fixed(buffer);
    try writer.writeAll(prefix);
    for (0..count) |_| try writer.writeAll(item);
    try writer.writeAll(suffix);
    try writer.writeByte(0);
    return buffer[0 .. writer.end - 1 :0];
}

// SPEC §1.11 and §5: collection limits reject one above each permitted maximum.
test "listener upstream and nodata count boundaries" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var buffer: [8192]u8 = undefined;
    try harness.rejects(".{ .listen = .{}, .zones = .{} }", "listen must not be empty");
    const cases = .{
        .{ ".{ .zones = .{}, .listen = .{", "\"127.0.0.1:1053\",", 16, "} }", "listen exceeds" },
        .{
            ".{ .zones = .{ .{ .suffix = \".\", .upstreams = .{",
            upstream ++ ",",
            16,
            "} } } }",
            "upstreams exceeds",
        },
        .{ zone_start ++ ".nodata = .{", ".AAAA,", 256, "}" ++ zone_end, "nodata exceeds" },
    };
    inline for (cases) |case| {
        try harness.parse(try listSource(&buffer, case[0], case[1], case[2], case[3]));
        try harness.rejects(
            try listSource(&buffer, case[0], case[1], case[2] + 1, case[3]),
            case[4],
        );
    }
}

fn zonesSource(buffer: []u8, count: u16, cache: []const u8) ![:0]const u8 {
    var writer: std.Io.Writer = .fixed(buffer);
    try writer.writeAll(".{ .zones = .{");
    for (0..count) |index| {
        try writer.print(".{{ .suffix = \"z{d}\", .cache = {s}, .upstreams = .{{{s}}} }},", .{
            index, cache, upstream,
        });
    }
    try writer.writeAll("} }");
    try writer.writeByte(0);
    return buffer[0 .. writer.end - 1 :0];
}

// SPEC §1.11 and §5: cache capacity counts both classes and all zones without overflow.
test "zone and aggregate cache capacity boundaries" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var buffer: [16384]u8 = undefined;
    try harness.parse(try zonesSource(&buffer, 64, "null"));
    try equal(64, harness.parsed.zones.len);
    try harness.rejects(try zonesSource(&buffer, 65, "null"), "zones exceeds 64");
    const cache = ".{ .capacity = 100000 }";
    try harness.parse(try zonesSource(&buffer, 5, cache));
    try harness.rejects(try zonesSource(&buffer, 6, cache), "capacity exceeds 1000000");
    try harness.parse(".{ .zones = .{} }");
    var name: config.Name = .{};
    try name.fromText("example.org.");
    try equal(null, config.route(&harness.parsed, &name));
}

// SPEC §5; RFC 1035 §2.3.4: suffix label and total wire length bounds apply before use.
test "configuration suffix name boundaries" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const prefix = ".{ .zones = .{ .{ .suffix = \"";
    const suffix = "\", .upstreams = .{" ++ upstream ++ "} } } }";
    const maximum = "a" ** 63 ++ "." ++ "b" ** 63 ++ "." ++ "c" ** 63 ++ "." ++ "d" ** 61;
    try harness.parse(prefix ++ maximum ++ suffix);
    try equal(254, harness.parsed.zones[0].suffix.len);
    try harness.parse(prefix ++ maximum ++ "." ++ suffix);
    const invalid = .{ "", "..", ".ts.net", "ts..net", "ts.net..", "a" ** 64, maximum ++ "d" };
    inline for (invalid) |name| try harness.rejects(prefix ++ name ++ suffix, "invalid DNS suffix");
}

// SPEC §5: malformed addresses, TLS identities, and paths fail during config load.
test "address TLS name and hosts path validation" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const invalid = .{ "", "host:", "host:0", "host:65536", "host:-1", "[::1", "::1", "a b:53" };
    inline for (invalid) |address| {
        try harness.rejects(
            ".{ .listen = .{\"" ++ address ++ "\"}, .zones = .{} }",
            "invalid listener address",
        );
        try harness.rejects(
            ".{ .zones = .{ .{ .suffix = \".\", .upstreams = .{ " ++
                ".{ .address = \"" ++ address ++ "\" } } } } }",
            "invalid upstream address",
        );
    }
    inline for (.{ "", "a b", "a\\x00b", "-bad", "bad-", "a..b" }) |name| {
        try harness.rejects(
            ".{ .zones = .{ .{ .suffix = \".\", .upstreams = .{ " ++
                ".{ .address = \"127.0.0.1\", .tls = .{ .server_name = \"" ++
                name ++ "\" } } } } } }",
            "TLS server_name",
        );
    }
    try harness.parse(zone_start ++ ".hosts = .{ .path = \"" ++ "x" ** 4096 ++ "\" }" ++ zone_end);
    try harness.rejects(
        zone_start ++ ".hosts = .{ .path = \"" ++ "x" ** 4097 ++ "\" }" ++ zone_end,
        "path exceeds 4096",
    );
}

// SPEC §4–5: failed file loading reports the real path and an I/O reason.
test "file loading failure diagnostic" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var source: [config.source_bytes_max + 2]u8 = undefined;
    harness.diagnostic.path = "tests/no-such-config.zon";
    try std.testing.expectError(error.InvalidConfig, config.load(
        &harness.parsed,
        std.testing.io,
        &source,
        harness.workspace,
        &harness.diagnostic,
    ));
    try std.testing.expectFmt(
        "tests/no-such-config.zon:1:1: error: FileNotFound\n",
        "{f}",
        .{&harness.diagnostic},
    );
}

// SPEC §1.11 and §5: successful parsed strings outlive the source buffer, not the workspace.
test "configuration source storage can be released after parsing" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    var source: [minimal.len:0]u8 = undefined;
    @memcpy(&source, minimal);
    source[minimal.len] = 0;
    try harness.parse(&source);
    @memset(source[0..minimal.len], 'x');
    try strings("127.0.0.1:1053", harness.parsed.zones[0].upstreams[0].address);
    try strings(".", harness.parsed.zones[0].suffix);
}
