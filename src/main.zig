const std = @import("std");
const config = @import("config.zig");
const builtin = @import("builtin");
const runtime = @import("runtime.zig");

pub fn main(init: std.process.Init) void {
    startup(&init);
    std.process.exit(1);
}

fn startup(init: *const std.process.Init) void {
    var iterator = init.minimal.args.iterate();
    _ = iterator.next();
    var arguments: [3][]const u8 = undefined;
    var count: u8 = 0;
    while (iterator.next()) |argument| {
        if (count == arguments.len) break;
        arguments[count] = argument;
        count += 1;
    }
    const path = config.configPath(arguments[0..count]) catch {
        std.debug.print("z53: usage: z53 [-c path]\n", .{});
        return;
    };
    var diagnostic: config.Diagnostic = .{ .path = path };
    const workspace = init.gpa.alloc(u8, config.workspace_bytes_max) catch {
        std.debug.print("{s}:1:1: error: configuration workspace allocation failed\n", .{path});
        return;
    };
    defer init.gpa.free(workspace);
    var source: [config.source_bytes_max + 2]u8 = undefined;
    var parsed: config.Config = undefined;
    config.load(&parsed, init.io, &source, workspace, &diagnostic) catch {
        std.debug.print("{f}", .{&diagnostic});
        return;
    };
    if (builtin.os.tag != .linux) {
        std.debug.print("z53: DNS service is not implemented yet\n", .{});
        return;
    }
    const service = init.gpa.create(runtime.Runtime) catch {
        std.debug.print("z53: runtime allocation failed\n", .{});
        return;
    };
    defer init.gpa.destroy(service);
    service.init(init.gpa, init.io, &parsed) catch |err| {
        std.debug.print("z53: startup: {s}\n", .{@errorName(err)});
        return;
    };
    defer service.deinit();
    while (service.step() catch |err| {
        std.debug.print("z53: runtime: {s}\n", .{@errorName(err)});
        return;
    }) {}
}
