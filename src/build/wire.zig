const std = @import("std");

pub fn add(
    b: *std.Build,
    target: *const std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    ztest: *std.Build.Dependency,
    all: *std.Build.Step,
    compile: *std.Build.Step,
) void {
    const wire = b.createModule(.{
        .root_source_file = b.path("src/wire.zig"),
        .target = target.*,
        .optimize = optimize,
        .link_libc = true,
    });
    const options: std.Build.TestOptions = .{
        .root_module = wire,
        .filters = &.{"WireTests"},
        .test_runner = .{ .path = ztest.path("src/test_runner.zig"), .mode = .simple },
    };
    compile.dependOn(&b.addTest(options).step);
    const run = b.addRunArtifact(b.addTest(options));
    run.has_side_effects = true;
    run.setEnvironmentVariable("ZTEST_VERBOSE", "1");
    run.setEnvironmentVariable("ZTEST_PLAIN", "1");
    const step = b.step("test-wire", "Run inline DNS codec tests");
    step.dependOn(&run.step);
    const gate = b.addSystemCommand(&.{"bash"});
    gate.addFileArg(b.path("tests/fuzz-gate.sh"));
    gate.has_side_effects = true;
    step.dependOn(&gate.step);
    all.dependOn(step);
    const fuzz_step = b.step("fuzz", "Fuzz DNS decode and rewrite with --fuzz");
    addFuzz(b, target, optimize, fuzz_step, "fuzz DNS decoder");
    addFuzz(b, target, optimize, fuzz_step, "fuzz structured DNS");
}

fn addFuzz(
    b: *std.Build,
    target: *const std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    step: *std.Build.Step,
    filter: []const u8,
) void {
    const fuzz = b.addTest(.{
        // The default x86 backend emits no fuzz coverage instrumentation in Zig 0.16.
        .use_llvm = true,
        .filters = &.{filter},
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/wire.zig"),
            // Zig 0.16's fuzz error printer passes builtin.StackTrace to debug.StackTrace.
            // Only disable returned-error traces here; safety and panic traces stay on.
            .error_tracing = false,
            .target = target.*,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    // Zig's default runner supplies the fuzz server protocol.
    const fuzz_run = b.addRunArtifact(fuzz);
    fuzz_run.has_side_effects = true;
    step.dependOn(&fuzz_run.step);
}
