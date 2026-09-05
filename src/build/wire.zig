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
    });
    const module = b.createModule(.{
        .root_source_file = b.path("tests/wire.zig"),
        .target = target.*,
        .optimize = optimize,
        .imports = &.{.{ .name = "wire", .module = wire }},
    });
    const options: std.Build.TestOptions = .{
        .root_module = module,
        .test_runner = .{ .path = ztest.path("src/test_runner.zig"), .mode = .simple },
    };
    module.link_libc = true;
    compile.dependOn(&b.addTest(options).step);
    const run = b.addRunArtifact(b.addTest(options));
    run.has_side_effects = true;
    run.setEnvironmentVariable("ZTEST_VERBOSE", "1");
    run.setEnvironmentVariable("ZTEST_PLAIN", "1");
    const step = b.step("test-wire", "Run bounded DNS codec tests");
    step.dependOn(&run.step);
    const gate = b.addSystemCommand(&.{"bash"});
    gate.addFileArg(b.path("tests/fuzz-gate.sh"));
    gate.has_side_effects = true;
    step.dependOn(&gate.step);
    all.dependOn(step);
    const fuzz_step = b.step("fuzz", "Fuzz DNS decode and rewrite with --fuzz");
    addFuzz(b, target, optimize, wire, fuzz_step, "decoder");
    addFuzz(b, target, optimize, wire, fuzz_step, "structured");
}

fn addFuzz(
    b: *std.Build,
    target: *const std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    wire: *std.Build.Module,
    step: *std.Build.Step,
    filter: []const u8,
) void {
    const fuzz = b.addTest(.{
        .filters = &.{filter},
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/fuzz.zig"),
            // Zig 0.16's fuzz error printer passes builtin.StackTrace to debug.StackTrace.
            // Only disable returned-error traces here; safety and panic traces stay on (#1).
            .error_tracing = false,
            .target = target.*,
            .optimize = optimize,
            .imports = &.{.{ .name = "wire", .module = wire }},
        }),
    });
    // SPEC §9.3: Zig's default runner supplies the fuzz server protocol.
    const fuzz_run = b.addRunArtifact(fuzz);
    fuzz_run.has_side_effects = true;
    step.dependOn(&fuzz_run.step);
}
