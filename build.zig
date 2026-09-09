const std = @import("std");
const wire = @import("src/build/wire.zig");
const benchmark = @import("src/build/benchmark.zig");
const config = @import("src/build/config.zig");
const resolver = @import("src/build/resolver.zig");
const runtime = @import("src/build/runtime.zig");

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
    b.step("run", "Run z53 (local responses only)").dependOn(&run.step);
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
    // SPEC §9.5: sandbox checks select TLS APIs without a host trust-store dependency.
    const filter = b.option([]const u8, "unit-filter", "Select a foundation test");
    const options: std.Build.TestOptions = .{
        .filters = if (filter) |value| &.{value} else &.{},
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
    addSupportTests(b, executable, ztest, test_step, test_compile);
    runtime.add(b, executable, ztest, test_step, test_compile);
    config.add(b, executable, ztest, test_step, test_compile);
    resolver.add(b, executable, ztest, test_step, test_compile);
    benchmark.addSmoke(b, &target, tls, test_step, test_compile);
    wire.add(
        b,
        &target,
        executable.root_module.optimize.?,
        ztest,
        test_step,
        test_compile,
    );
}

fn addSupportTests(
    b: *std.Build,
    executable: *std.Build.Step.Compile,
    ztest: *std.Build.Dependency,
    all: *std.Build.Step,
    compile: *std.Build.Step,
) void {
    const suites = .{
        .{ "test-containers", "src/array_buffer.zig", "Run inline container tests" },
        .{ "test-diagnostics", "src/runtime/failure.zig", "Run inline diagnostic tests" },
    };
    inline for (suites) |suite| {
        const options: std.Build.TestOptions = .{
            .root_module = b.createModule(.{
                .root_source_file = b.path(suite[1]),
                .target = executable.root_module.resolved_target.?,
                .optimize = executable.root_module.optimize,
                .imports = &.{.{
                    .name = "ztls",
                    .module = executable.root_module.import_table.get("ztls").?,
                }},
                .link_libc = true,
            }),
            .test_runner = .{ .path = ztest.path("src/test_runner.zig"), .mode = .simple },
        };
        compile.dependOn(&b.addTest(options).step);
        const run = b.addRunArtifact(b.addTest(options));
        run.has_side_effects = true;
        run.setEnvironmentVariable("ZTEST_VERBOSE", "1");
        run.setEnvironmentVariable("ZTEST_PLAIN", "1");
        const step = b.step(suite[0], suite[2]);
        step.dependOn(&run.step);
        all.dependOn(step);
    }
}
