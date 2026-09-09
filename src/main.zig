const std = @import("std");
const print = std.debug.print;
const process = std.process;

const config = @import("config.zig");
const runtime = @import("runtime.zig");

pub fn main(init: process.Init) void {
    startup(&init);
    process.exit(1);
}

fn startup(init: *const process.Init) void {
    const arena = init.arena.allocator();
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
        print("z53: usage: z53 [-c path]\n", .{});
        return;
    };
    var diagnostic: config.Diagnostic = .{ .path = path };
    const workspace = arena.create([config.workspace_bytes_max]u8) catch {
        print("{s}:1:1: error: configuration workspace allocation failed\n", .{path});
        return;
    };
    var source: [config.source_bytes_max + 2]u8 = undefined;
    var parsed: config.Config = undefined;
    config.load(&parsed, init.io, &source, workspace, &diagnostic) catch {
        print("{f}", .{&diagnostic});
        return;
    };
    const service = arena.create(runtime.Runtime) catch {
        print("z53: runtime allocation failed\n", .{});
        return;
    };
    service.init(init.gpa, init.io, &parsed) catch |err| {
        print("z53: startup: {s}\n", .{@errorName(err)});
        return;
    };
    defer service.deinit();
    while (service.step() catch |err| {
        print("z53: runtime: {s}\n", .{@errorName(err)});
        return;
    }) {}
}
