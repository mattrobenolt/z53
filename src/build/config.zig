const std = @import("std");

pub fn add(
    b: *std.Build,
    executable: *std.Build.Step.Compile,
    ztest: *std.Build.Dependency,
    all: *std.Build.Step,
    compile: *std.Build.Step,
) void {
    const module = b.createModule(.{
        .root_source_file = b.path("src/config.zig"),
        .target = executable.root_module.resolved_target.?,
        .optimize = executable.root_module.optimize,
    });
    const options: std.Build.TestOptions = .{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/config.zig"),
            .target = executable.root_module.resolved_target.?,
            .optimize = executable.root_module.optimize,
            .imports = &.{.{ .name = "config", .module = module }},
        }),
        .test_runner = .{ .path = ztest.path("src/test_runner.zig"), .mode = .simple },
    };
    options.root_module.link_libc = true;
    compile.dependOn(&b.addTest(options).step);
    const run = b.addRunArtifact(b.addTest(options));
    run.setCwd(b.path("."));
    run.has_side_effects = true;
    run.setEnvironmentVariable("ZTEST_VERBOSE", "1");
    run.setEnvironmentVariable("ZTEST_PLAIN", "1");
    const step = b.step("test-config", "Run typed configuration and suffix routing tests");
    step.dependOn(&run.step);
    all.dependOn(step);
    // SPEC §4–6: CLI diagnostics and successful parsing stay independent of sockets.
    const invalid = b.addRunArtifact(executable);
    invalid.setCwd(b.path("."));
    invalid.addArgs(&.{ "-c", "tests/fixtures/config-invalid.zon" });
    invalid.expectExitCode(1);
    invalid.expectStdOutEqual("");
    invalid.expectStdErrEqual(
        "tests/fixtures/config-invalid.zon:5:26: error: zone requires at least one upstream\n",
    );
    step.dependOn(&invalid.step);
    const missing = b.addRunArtifact(executable);
    missing.addArg("-c");
    missing.expectExitCode(1);
    missing.expectStdOutEqual("");
    missing.expectStdErrEqual("z53: usage: z53 [-c path]\n");
    step.dependOn(&missing.step);
}
