const std = @import("std");
const config = @import("../config.zig");
const names = @import("../wire/name.zig");
const endpoint = @import("endpoint.zig");
const Index = std.zig.Zoir.Node.Index;

pub const Context = struct {
    diagnostics: *const std.zon.parse.Diagnostics,
    diagnostic: *config.Diagnostic,

    pub fn validate(
        self: *Context,
        allocator: std.mem.Allocator,
        target: *config.Config,
    ) config.Error!void {
        const listen_node = self.field(.root, "listen");
        if (target.listen.len == 0) return self.fail(listen_node, "listen must not be empty");
        if (target.listen.len > config.listeners_max) {
            return self.fail(listen_node, "listen exceeds 16 addresses");
        }
        for (target.listen, 0..) |address, index| {
            var parsed: config.Endpoint = undefined;
            parsed.parse(address, 53) catch {
                return self.fail(self.element(listen_node, index), "invalid listener address");
            };
        }
        const zones_node = self.field(.root, "zones");
        if (target.zones.len > config.zones_max) {
            return self.fail(zones_node, "zones exceeds 64 entries");
        }
        var entries: u32 = 0;
        for (target.zones, 0..) |*zone, index| {
            const node = self.element(zones_node, index);
            try self.zoneValidate(allocator, zone, node);
            for (target.zones[0..index]) |*previous| {
                if (std.mem.eql(u8, previous.suffix, zone.suffix)) {
                    return self.fail(self.field(node, "suffix"), "duplicate zone suffix");
                }
            }
            if (zone.cache) |cache| {
                entries += cache.capacity * 2;
                if (entries > config.cache_entries_max) {
                    return self.fail(
                        self.field(node, "cache"),
                        "total positive and denial capacity exceeds 1000000 entries",
                    );
                }
            }
        }
    }

    fn zoneValidate(
        self: *Context,
        allocator: std.mem.Allocator,
        zone: *config.Zone,
        node: Index,
    ) config.Error!void {
        var name: names.Name = .{};
        name.fromText(zone.suffix) catch {
            return self.fail(
                self.field(node, "suffix"),
                "invalid DNS suffix: labels <=63 bytes, wire name <=255 bytes",
            );
        };
        const extra: usize = @intFromBool(zone.suffix[zone.suffix.len - 1] != '.');
        const canonical = allocator.alloc(u8, zone.suffix.len + extra) catch {
            return self.fail(node, "configuration workspace exhausted");
        };
        for (zone.suffix, 0..) |byte, index| canonical[index] = std.ascii.toLower(byte);
        canonical[canonical.len - 1] = '.';
        zone.suffix = canonical;
        const upstreams_node = self.field(node, "upstreams");
        if (zone.upstreams.len == 0) {
            return self.fail(upstreams_node, "zone requires at least one upstream");
        }
        if (zone.upstreams.len > config.upstreams_max) {
            return self.fail(upstreams_node, "upstreams exceeds 16 entries");
        }
        for (zone.upstreams, 0..) |*upstream, index| {
            try self.upstreamValidate(upstream, self.element(upstreams_node, index));
        }
        if (zone.nodata.len > 256) {
            return self.fail(self.field(node, "nodata"), "nodata exceeds 256 types");
        }
        try self.duration(
            zone.health_check_interval_s,
            self.field(node, "health_check_interval_s"),
        );
        try self.duration(zone.read_timeout_s, self.field(node, "read_timeout_s"));
        try self.duration(zone.conn_expire_s, self.field(node, "conn_expire_s"));
        if (zone.hosts) |hosts| try self.hostsValidate(&hosts, self.field(node, "hosts"));
        if (zone.cache) |*cache| try self.cacheValidate(cache, self.field(node, "cache"));
    }

    fn hostsValidate(self: *Context, hosts: *const config.Hosts, node: Index) config.Error!void {
        const path_node = self.field(node, "path");
        if (hosts.path.len == 0) return self.fail(path_node, "hosts path must not be empty");
        if (hosts.path.len > 4096) return self.fail(path_node, "hosts path exceeds 4096 bytes");
        if (std.mem.indexOfScalar(u8, hosts.path, 0) != null) {
            return self.fail(path_node, "hosts path contains NUL");
        }
    }

    fn upstreamValidate(
        self: *Context,
        upstream: *const config.Upstream,
        node: Index,
    ) config.Error!void {
        var parsed: config.Endpoint = undefined;
        parsed.parse(upstream.address, if (upstream.tls != null) 853 else 53) catch {
            return self.fail(self.field(node, "address"), "invalid upstream address");
        };
        if (upstream.tls) |tls| {
            endpoint.validateHost(tls.server_name) catch {
                return self.fail(
                    self.field(self.field(node, "tls"), "server_name"),
                    "TLS server_name must be a nonempty DNS hostname",
                );
            };
        }
    }

    fn cacheValidate(self: *Context, cache: *const config.Cache, node: Index) config.Error!void {
        if (cache.min_ttl_s > cache.max_ttl_s) {
            return self.fail(self.field(node, "min_ttl_s"), "min_ttl_s exceeds max_ttl_s");
        }
        if (cache.denialMaximum() < 5) {
            return self.fail(node, "effective denial maximum must be at least 5 seconds");
        }
        if (cache.capacity == 0) {
            return self.fail(
                self.field(node, "capacity"),
                "cache capacity must be positive; use cache = null to disable",
            );
        }
        if (cache.capacity > config.cache_capacity_max) {
            return self.fail(
                self.field(node, "capacity"),
                "cache capacity exceeds 100000 entries per class",
            );
        }
    }

    fn duration(self: *Context, seconds: f64, node: Index) config.Error!void {
        if (!std.math.isFinite(seconds)) return self.fail(node, "duration must be finite");
        if (seconds < 0.001) return self.fail(node, "duration must be at least 0.001 seconds");
        if (seconds > 86400) return self.fail(node, "duration exceeds 86400 seconds");
    }

    fn field(self: *const Context, parent: Index, name: []const u8) Index {
        switch (parent.get(self.diagnostics.zoir)) {
            .struct_literal => |literal| {
                for (literal.names, 0..) |key, index| {
                    if (std.mem.eql(u8, key.get(self.diagnostics.zoir), name)) {
                        return literal.vals.at(@intCast(index));
                    }
                }
            },
            else => {},
        }
        // Defaults have no token: identify their containing object instead.
        return parent;
    }

    fn element(self: *const Context, parent: Index, index: usize) Index {
        return switch (parent.get(self.diagnostics.zoir)) {
            .array_literal => |array| array.at(@intCast(index)),
            else => parent,
        };
    }

    fn fail(self: *Context, node: Index, reason: []const u8) config.Error {
        const ast = &self.diagnostics.ast;
        const token = ast.firstToken(node.getAstNode(self.diagnostics.zoir));
        const location = ast.tokenLocation(0, token);
        self.diagnostic.line = @intCast(location.line + 1);
        self.diagnostic.column = @intCast(location.column + 1);
        return self.diagnostic.set(reason);
    }
};
