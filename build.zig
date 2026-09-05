const std = @import("std");
const wire = @import("src/build/wire.zig");
const benchmark = @import("src/build/benchmark.zig");
const config = @import("src/build/config.zig");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const tls = b.dependency("ztls", .{
        .target = target,
        .optimize = optimize,
        .@"crypto-backend" = "openssl",
    }).module("ztls");
    // Zig keeps the first library entry, so update it rather than append a duplicate.
    for (tls.link_objects.items) |*object| {
        switch (object.*) {
            .system_lib => |*library| {
                if (std.mem.eql(u8, library.name, "crypto")) library.use_pkg_config = .force;
            },
            else => {},
        }
    }
    const executable_options: std.Build.ExecutableOptions = .{
        .name = "z53",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "ztls", .module = tls }},
        }),
    };
    const executable = b.addExecutable(executable_options);
    b.installArtifact(executable);
    const run = b.addRunArtifact(executable);
    if (b.args) |args| run.addArgs(args);
    b.step("run", "Run z53 (not yet a DNS server)").dependOn(&run.step);
    b.step("check", "Check compilation without linking").dependOn(
        &b.addExecutable(executable_options).step,
    );
    addTests(b, executable, tls);
}

fn addTests(b: *std.Build, executable: *std.Build.Step.Compile, tls: *std.Build.Module) void {
    const test_step = b.step("test", "Run foundation tests with ztest");
    const test_compile = b.step("test-compile", "Check unit test compilation without linking");
    const ztest = b.lazyDependency("ztest", .{}) orelse return;
    const target = executable.root_module.resolved_target.?;
    const unit_step = b.step("test-unit", "Run dependency API and startup tests");
    test_step.dependOn(unit_step);
    const options: std.Build.TestOptions = .{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/foundation.zig"),
            .target = target,
            .optimize = executable.root_module.optimize,
            .imports = &.{.{ .name = "ztls", .module = tls }},
        }),
        .test_runner = .{ .path = ztest.path("src/test_runner.zig"), .mode = .simple },
    };
    options.root_module.link_libc = true;
    test_compile.dependOn(&b.addTest(options).step);
    const run_tests = b.addRunArtifact(b.addTest(options));
    run_tests.has_side_effects = true;
    run_tests.setEnvironmentVariable("ZTEST_VERBOSE", "1");
    run_tests.setEnvironmentVariable("ZTEST_PLAIN", "1");
    unit_step.dependOn(&run_tests.step);
    // SPEC §4: stderr only. A foundation binary must not claim to serve DNS.
    const startup = b.addRunArtifact(executable);
    startup.addArgs(&.{ "-c", "examples/launchpad.zon" });
    startup.setCwd(b.path("."));
    startup.expectExitCode(1);
    startup.expectStdOutEqual("");
    startup.expectStdErrEqual("z53: DNS service is not implemented yet\n");
    unit_step.dependOn(&startup.step);
    config.add(b, executable, ztest, test_step, test_compile);
    benchmark.addSmoke(b, &target, test_step);
    wire.add(
        b,
        &target,
        executable.root_module.optimize.?,
        ztest,
        test_step,
        test_compile,
    );
}
