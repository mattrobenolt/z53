const std = @import("std");

pub fn add(
    b: *std.Build,
    executable: *std.Build.Step.Compile,
    ztest: *std.Build.Dependency,
    all: *std.Build.Step,
    compile: *std.Build.Step,
) void {
    const module = b.createModule(.{
        .root_source_file = b.path("src/resolver.zig"),
        .target = executable.root_module.resolved_target.?,
        .optimize = executable.root_module.optimize,
    });
    const root = b.createModule(.{
        .root_source_file = b.path("tests/resolver.zig"),
        .target = executable.root_module.resolved_target.?,
        .optimize = executable.root_module.optimize,
        .imports = &.{.{ .name = "resolver", .module = module }},
        .link_libc = true,
    });
    const options: std.Build.TestOptions = .{
        .root_module = root,
        .test_runner = .{ .path = ztest.path("src/test_runner.zig"), .mode = .simple },
    };
    compile.dependOn(&b.addTest(options).step);
    const run = b.addRunArtifact(b.addTest(options));
    run.has_side_effects = true;
    run.setEnvironmentVariable("ZTEST_VERBOSE", "1");
    run.setEnvironmentVariable("ZTEST_PLAIN", "1");
    const step = b.step("test-resolver", "Run synthetic, hosts replacement, and rotation tests");
    step.dependOn(&run.step);
    all.dependOn(step);
}
