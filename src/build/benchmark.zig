const std = @import("std");

pub fn addSmoke(
    b: *std.Build,
    target: *const std.Build.ResolvedTarget,
    tls: *std.Build.Module,
    stdx: *std.Build.Module,
    testingx: *std.Build.Dependency,
    test_step: *std.Build.Step,
    test_compile: *std.Build.Step,
) void {
    const smoke = b.step("bench-smoke", "Run eight iterations of each DNS benchmark");
    // Benchmarks always build ReleaseSafe, independently of the daemon build options.
    const pipeline = b.createModule(.{
        .root_source_file = b.path("src/runtime.zig"),
        .target = target.*,
        .optimize = .ReleaseSafe,
        .imports = &.{
            .{ .name = "tls", .module = tls },
            .{ .name = "stdx", .module = stdx },
        },
    });
    const options: std.Build.ExecutableOptions = .{
        .name = "dns-benchmark",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/benchmark.zig"),
            .target = target.*,
            .optimize = .ReleaseSafe,
            .link_libc = true,
            .imports = &.{
                .{ .name = "testingx", .module = testingx.module("testingx") },
                .{ .name = "pipeline", .module = pipeline },
            },
        }),
    };
    test_compile.dependOn(&b.addExecutable(options).step);
    const executable = b.addExecutable(options);
    const run = b.addRunArtifact(executable);
    run.addArg("smoke");
    run.has_side_effects = true;
    smoke.dependOn(&run.step);
    test_step.dependOn(&run.step);
    const baseline = b.addRunArtifact(executable);
    if (b.args) |arguments| baseline.addArgs(arguments);
    baseline.has_side_effects = true;
    b.step("bench", "Run bounded DNS baselines (ReleaseSafe)").dependOn(&baseline.step);
    b.step("bench-build", "Install the ReleaseSafe DNS benchmark for perf").dependOn(
        &b.addInstallArtifact(executable, .{}).step,
    );
}
