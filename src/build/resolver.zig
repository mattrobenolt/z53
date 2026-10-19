const std = @import("std");

pub fn add(
    b: *std.Build,
    executable: *std.Build.Step.Compile,
    stdx: *std.Build.Module,
    testingx: *std.Build.Dependency,
    all: *std.Build.Step,
    compile: *std.Build.Step,
) void {
    const module = b.createModule(.{
        .root_source_file = b.path("src/resolver.zig"),
        .target = executable.root_module.resolved_target.?,
        .optimize = executable.root_module.optimize,
        .link_libc = true,
        .imports = &.{.{ .name = "stdx", .module = stdx }},
    });
    const options: std.Build.TestOptions = .{
        .root_module = module,
        .filters = &.{"ResolverTests"},
        .test_runner = .{ .path = testingx.path("src/runner.zig"), .mode = .simple },
    };
    compile.dependOn(&b.addTest(options).step);
    const run = b.addRunArtifact(b.addTest(options));
    run.has_side_effects = true;
    const step = b.step("test-resolver", "Run synthetic, hosts replacement, and rotation tests");
    step.dependOn(&run.step);
    all.dependOn(step);
}
