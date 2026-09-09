const std = @import("std");

pub fn add(
    b: *std.Build,
    executable: *std.Build.Step.Compile,
    ztest: *std.Build.Dependency,
    all: *std.Build.Step,
    compile: *std.Build.Step,
) void {
    const module = b.createModule(.{
        .root_source_file = b.path("src/runtime.zig"),
        .target = executable.root_module.resolved_target.?,
        .optimize = executable.root_module.optimize,
        .imports = &.{.{
            .name = "ztls",
            .module = executable.root_module.import_table.get("ztls").?,
        }},
        .link_libc = true,
    });
    const filter = b.option([]const u8, "runtime-filter", "Select a runtime regression");
    const options: std.Build.TestOptions = .{
        .filters = if (filter) |value| &.{value} else &.{},
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/runtime.zig"),
            .target = executable.root_module.resolved_target.?,
            .optimize = executable.root_module.optimize,
            .imports = &.{.{ .name = "runtime", .module = module }},
            .link_libc = true,
        }),
        .test_runner = .{ .path = ztest.path("src/test_runner.zig"), .mode = .simple },
    };
    compile.dependOn(&b.addTest(options).step);
    const run = b.addRunArtifact(b.addTest(options));
    run.has_side_effects = true;
    run.setEnvironmentVariable("ZTEST_VERBOSE", "1");
    run.setEnvironmentVariable("ZTEST_PLAIN", "1");
    const step = b.step("test-runtime", "Run native transport and lifecycle tests");
    step.dependOn(&run.step);
    all.dependOn(step);
    const unit_options: std.Build.TestOptions = .{
        .root_module = module,
        .filters = &.{"RuntimeUnitTests"},
        .test_runner = .{ .path = ztest.path("src/test_runner.zig"), .mode = .simple },
    };
    compile.dependOn(&b.addTest(unit_options).step);
    const unit_run = b.addRunArtifact(b.addTest(unit_options));
    unit_run.setCwd(b.path("."));
    unit_run.has_side_effects = true;
    unit_run.setEnvironmentVariable("ZTEST_VERBOSE", "1");
    unit_run.setEnvironmentVariable("ZTEST_PLAIN", "1");
    const unit_step = b.step("test-runtime-unit", "Run inline runtime unit tests without sockets");
    unit_step.dependOn(&unit_run.step);
    all.dependOn(unit_step);
}
