const std = @import("std");
const f = @import("fixture.zig");
const hosts = f.resolver.hosts;
const testing = std.testing;

fn write(directory: std.Io.Dir, source: []const u8, seconds: i64) !void {
    try directory.writeFile(testing.io, .{ .sub_path = "hosts", .data = source });
    const file = try directory.openFile(testing.io, "hosts", .{});
    defer file.close(testing.io);
    try file.setTimestamps(testing.io, .{
        .modify_timestamp = .{ .new = .fromNanoseconds(@as(i96, seconds) * std.time.ns_per_s) },
    });
}

// SPEC §3.5: real file reads replace only changed snapshots and preserve deleted-file data.
test "hosts file reload observes mtime and retains old table on I/O and capacity failure" {
    var temporary = testing.tmpDir(.{});
    defer temporary.cleanup();
    var first: [1]hosts.Entry = undefined;
    var second: [1]hosts.Entry = undefined;
    var store: hosts.Store = undefined;
    store.init(&first, &second);
    const source = try testing.allocator.alloc(u8, hosts.source_bytes_max + 1);
    defer testing.allocator.free(source);
    try write(temporary.dir, "192.0.2.1 old\n", 100);
    try testing.expectEqual(.replaced, try store.load(testing.io, temporary.dir, "hosts", source));
    const active = store.table();
    try testing.expectEqual(.unchanged, try store.load(testing.io, temporary.dir, "hosts", source));
    try testing.expect(active == store.table());
    try write(temporary.dir, "192.0.2.2 new\n", 100);
    try testing.expectEqual(.unchanged, try store.load(testing.io, temporary.dir, "hosts", source));
    try write(temporary.dir, "192.0.2.2 new alias\n", 101);
    try testing.expectError(
        error.TableFull,
        store.load(testing.io, temporary.dir, "hosts", source),
    );
    try testing.expect(active == store.table());
    try testing.expectEqual(@as(?i128, 100 * std.time.ns_per_s), store.mtime);
    try write(temporary.dir, "192.0.2.2 new\n", 101);
    try testing.expectEqual(.replaced, try store.load(testing.io, temporary.dir, "hosts", source));
    try testing.expect(active != store.table());
    const replaced = store.table();
    try temporary.dir.deleteFile(testing.io, "hosts");
    try testing.expectError(
        error.FileNotFound,
        store.load(testing.io, temporary.dir, "hosts", source),
    );
    try testing.expect(replaced == store.table());
    try testing.expectEqual(@as(?i128, 101 * std.time.ns_per_s), store.mtime);
    try write(temporary.dir, "# empty\n", 102);
    try testing.expectEqual(.replaced, try store.load(testing.io, temporary.dir, "hosts", source));
    try testing.expectEqual(@as(u16, 0), store.table().count);
}

// SPEC §1.11, §3.5: bound file size and reject nonregular sources without publication.
test "hosts file size and regular file restrictions" {
    var temporary = testing.tmpDir(.{});
    defer temporary.cleanup();
    var first: [1]hosts.Entry = undefined;
    var second: [1]hosts.Entry = undefined;
    var store: hosts.Store = undefined;
    store.init(&first, &second);
    const source = try testing.allocator.alloc(u8, hosts.source_bytes_max + 1);
    defer testing.allocator.free(source);
    @memset(source, '\n');
    try write(temporary.dir, source, 100);
    try testing.expectError(
        error.SourceTooLarge,
        store.load(testing.io, temporary.dir, "hosts", source),
    );
    try testing.expectEqual(@as(?i128, null), store.mtime);
    try testing.expectError(
        error.NotRegularFile,
        store.load(testing.io, temporary.dir, ".", source),
    );
    try testing.expectEqual(@as(?i128, null), store.mtime);
    try write(temporary.dir, source[0..hosts.source_bytes_max], 101);
    try testing.expectEqual(.replaced, try store.load(testing.io, temporary.dir, "hosts", source));
}

const Fault = struct {
    var calls: u8 = 0;

    fn changed(userdata: ?*anyopaque, file: std.Io.File) std.Io.File.StatError!std.Io.File.Stat {
        var result = try testing.io.vtable.fileStat(userdata, file);
        calls += 1;
        if (calls == 2) result.mtime.nanoseconds += std.time.ns_per_s;
        return result;
    }

    fn unreadable(
        _: ?*anyopaque,
        _: std.Io.File,
        _: []const []u8,
        _: u64,
    ) std.Io.File.ReadPositionalError!usize {
        return error.InputOutput;
    }
};

// SPEC §3.5: deterministic Io faults reject a torn read and never publish an I/O failure.
test "hosts detects mid-read changes and read failure before snapshot publication" {
    var temporary = testing.tmpDir(.{});
    defer temporary.cleanup();
    var first: [1]hosts.Entry = undefined;
    var second: [1]hosts.Entry = undefined;
    var store: hosts.Store = undefined;
    store.init(&first, &second);
    try store.replace("192.0.2.1 old\n", 1);
    const active = store.table();
    const source = try testing.allocator.alloc(u8, hosts.source_bytes_max + 1);
    defer testing.allocator.free(source);
    try write(temporary.dir, "192.0.2.2 new\n", 100);
    var vtable = testing.io.vtable.*;
    vtable.fileStat = Fault.changed;
    const io: std.Io = .{ .userdata = testing.io.userdata, .vtable = &vtable };
    Fault.calls = 0;
    try testing.expectError(error.FileChanged, store.load(io, temporary.dir, "hosts", source));
    try testing.expect(active == store.table());
    try testing.expectEqual(@as(?i128, 1), store.mtime);
    vtable.fileStat = testing.io.vtable.fileStat;
    vtable.fileReadPositional = Fault.unreadable;
    try testing.expectError(error.InputOutput, store.load(io, temporary.dir, "hosts", source));
    try testing.expect(active == store.table());
    try testing.expectEqual(@as(?i128, 1), store.mtime);
}
