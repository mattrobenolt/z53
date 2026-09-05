//! SPEC §1.4 and §9.4: exercise the helper, without a DNS performance claim.
const std = @import("std");
const benchmark = @import("benchmark");

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    var arguments = try init.minimal.args.iterateAllocator(allocator);
    defer arguments.deinit();
    const options = try benchmark.Options.parse(&arguments, .{
        .benchtime = .{ .count = 8 },
        .io = init.io,
    });
    if (!try benchmark.runBenchmarks(allocator, &.{.{
        .name = "BenchmarkHelperSmoke",
        .func = smoke,
    }}, options)) return error.BenchmarkFailed;
}

fn smoke(timer: *benchmark.B) !void {
    var count: u32 = 0;
    while (try timer.loop()) {
        count += 1;
        benchmark.keepAlive(count);
    }
    if (count != 8) return error.UnexpectedIterationCount;
}
