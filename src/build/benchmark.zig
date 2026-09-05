const std = @import("std");

pub fn addSmoke(
    b: *std.Build,
    target: *const std.Build.ResolvedTarget,
    test_step: *std.Build.Step,
) void {
    const smoke = b.step("bench-smoke", "Check the benchmark helper, not DNS performance");
    const dependency = b.lazyDependency("benchmark", .{
        .target = target.*,
        .optimize = .ReleaseFast,
    }) orelse return;
    const module = dependency.module("benchmark");
    const executable = b.addExecutable(.{
        .name = "benchmark-smoke",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/benchmark.zig"),
            .target = target.*,
            .optimize = .ReleaseFast,
            .link_libc = true,
            .imports = &.{.{ .name = "benchmark", .module = module }},
        }),
    });
    const run = b.addRunArtifact(executable);
    run.has_side_effects = true;
    smoke.dependOn(&run.step);
    test_step.dependOn(&run.step);
}
