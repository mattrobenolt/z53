"""Finite one-at-a-time Darwin source controls for #1, not a mutation framework."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Control:
    name: str
    path: str
    old: str
    new: str
    test: str
    error: str
    assertion: str


RUNTIME = "src/runtime_darwin.zig"
KQUEUE = "src/runtime/kqueue.zig"
ADDRESS = "src/runtime/address_darwin.zig"
METADATA = "src/runtime/udp_darwin.zig"
RETAINED = "Darwin native retained EAGAIN bytes destinations and shared filters"
STALE = "Darwin native stale event identity and generation rejection"
FLAGS = "Darwin native nonblocking close-on-exec and no SIGPIPE"
QUOTA = "Darwin native accept quota timer recovery"
FRAME_READER = """    fn frame(self: *Harness, descriptor: system.fd_t, output: []u8) ![]const u8 {
        if (output.len < 2) return error.NoSpace;
        var length: usize = 0;
        var target: usize = 2;
        for (0..64) |_| {
            // #1: later frames must stay queued because this reader retains no trailing bytes.
            const received = try self.receive(descriptor, output[length..target]);
            if (received == 0) return error.UnexpectedEof;
            length += received;
            if (try wire.frame(output[0..length])) |value| return value.message;
            if (length == 2) {
                target = 2 + @as(usize, wire.integer(u16, output[0..2]));
                if (target > output.len) return error.NoSpace;
            }
        }
        return error.TestDeadline;
    }"""
FRAME_READER_OLD = """    fn frame(self: *Harness, descriptor: system.fd_t, output: []u8) ![]const u8 {
        var length: usize = 0;
        for (0..64) |_| {
            length += try self.receive(descriptor, output[length..]);
            if (try wire.frame(output[0..length])) |value| return value.message;
        }
        return error.TestDeadline;
    }"""
# Preserve assertion line numbers for the existing strict native gate.
FRAME_READER_OLD += "\n" * (FRAME_READER.count("\n") - FRAME_READER_OLD.count("\n"))
CONTROLS = [
    Control("r3-release", RUNTIME, ".AGAIN, .INTR => return,", ".AGAIN, .INTR => {},",
            RETAINED, "TestExpectedEqual", "try testing.expectEqual(index + 1, retainedCount(first.service));"),
    Control("r3-listener", RUNTIME,
            "return system.sendto(\n            self.listeners[listener].udp.?,",
            "return system.sendto(\n            self.listeners[listener * 0].udp.?,",
            RETAINED, "TestUnexpectedResult", "try testing.expect(received > 0);"),
    Control("r3-filter", RUNTIME, "const slot = send_start + @as(u32, listener);",
            "const slot = send_start + @as(u32, listener) * 0;",
            RETAINED, "TestExpectedEqual", "try testing.expectEqualSlices(u32, &.{ 1, 1 }, &counts);"),
    Control("r4-delete", KQUEUE,
            "if (system.kevent(self.descriptor, @ptrCast(&change), 1, &.{}, 0, null) < 0)\n"
            "            return error.RegistrationFailed;\n        const owner = &self.ownership[index];",
            "_ = change;\n        const owner = &self.ownership[index];",
            "Darwin native ready socket deletion sentinel and descriptor reuse",
            "TestExpectedEqual", "try testing.expectEqual(0, pending);"),
    Control("r4-identity", KQUEUE,
            "if (registration.ident != event.ident) return error.InvalidCompletion;", "",
            STALE, "TestExpectedError",
            "proctor.registrations[0].?.ident = @intCast(pair[1]);\n"
            "    try testing.expectError(error.InvalidCompletion, proctor.next());"),
    Control("r4-generation", KQUEUE,
            "try self.ownership[index].complete(event.udata, .terminal);",
            "try self.ownership[index].complete(self.ownership[index].token(index), .terminal);",
            STALE, "TestExpectedError",
            "try testing.expectEqual(0, result);\n"
            "    try testing.expectError(error.InvalidCompletion, proctor.next());"),
    Control("flags-nonblock", ADDRESS, "flags | nonblocking", "flags | (nonblocking & 0)",
            FLAGS, "TestUnexpectedResult", "try testing.expect(flags & nonblocking != 0);"),
    Control("flags-cloexec", ADDRESS, "@as(c_int, system.FD_CLOEXEC)", "@as(c_int, 0)",
            FLAGS, "TestUnexpectedResult",
            "try testing.expect(system.fcntl(descriptor, system.F.GETFD) & system.FD_CLOEXEC != 0);"),
    Control("flags-sigpipe", ADDRESS,
            "try option(descriptor, system.SOL.SOCKET, system.SO.NOSIGPIPE);", "",
            FLAGS, "TestExpectedEqual", "try testing.expectEqual(1, enabled);"),
    Control("startup-rollback", RUNTIME, "errdefer self.closeDescriptors();", "",
            "Darwin native immediate repeated restart after partial initialization",
            "TestUnexpectedResult", "try testing.expect(released != null);"),
    Control("reload-disabled", "src/runtime/pipeline.zig",
            "if (source.reload_s == 0) continue;", "",
            "Darwin native hosts reload timer failure retry and disabled checks", "TestExpectedEqual",
            "try testing.expect(try harness.service.step());\n"
            "    try testing.expectEqual(@as(u16, 0), store.table().count);\n    try harness.stop();"),
    Control("metadata-length", METADATA, "if (length != expected) return error.InvalidDatagram;",
            "if (length == 0) return error.InvalidDatagram;",
            "Darwin native malformed datagram metadata", "TestExpectedError",
            "try testing.expectError(error.InvalidDatagram, datagram.family(&source, source.len - 1));"),
    Control("metadata-embedded", METADATA, "if (source.len != expected) return error.InvalidDatagram;", "",
            "Darwin native malformed datagram metadata", "TestExpectedError",
            "try testing.expectError(\n        error.InvalidDatagram,\n"
            "        datagram.family(&source, @sizeOf(system.sockaddr.in)),\n    );"),
    Control("eof-buffered", KQUEUE,
            "// EOF is readiness too: recv drains buffered bytes before returning zero.",
            "if (event.flags & system.EV.EOF != 0) return error.CompletionFailed;",
            "Darwin native IPv6 UDP TCP and peer half close", "TestUnexpectedResult",
            "try testing.expect(response.len >= 12);"),
    Control("quota-rearm", RUNTIME, ".MFILE, .NFILE, .NOBUFS, .NOMEM => {},",
            ".MFILE, .NFILE, .NOBUFS, .NOMEM => try self.accept(listener),",
            QUOTA, "TestExpectedEqual",
            "try testing.expectEqual(null, harness.service.proctor.registrations[16]);\n"
            "    try testing.expectEqual(null, harness.service.descriptors[0]);"),
    Control("quota-timer", RUNTIME,
            "self.pipeline.reload(self.io, try now());\n            try self.resumeAccepts();",
            "self.pipeline.reload(self.io, try now());",
            QUOTA, "TestExpectedEqual",
            "try testing.expectEqual(generation + 1, harness.service.proctor.ownership[16].generation);"),
    Control("connect-error", "tests/runtime_darwin.zig", "if (failure != 0) {",
            "if (failure < 0) {",
            "Darwin native client completion rejects peer reset", "TestExpectedError",
            "try testing.expectError(error.ConnectFailed, finishConnect(descriptor));"),
    Control("frame-reader", "tests/runtime_darwin.zig", FRAME_READER, FRAME_READER_OLD,
            "Darwin native frame reader preserves a second queued frame", "TestExpectedEqual",
            "try testing.expectEqual(.ready, remaining);"),
]


def unique(source, text):
    if source.count(text) != 1:
        raise RuntimeError(f"Expected one exact source match: {text!r}")
    return source.index(text)


def assertion_lines(source, control):
    start = unique(source, control.assertion)
    first = source[:start].count("\n") + 1
    return range(first, first + control.assertion.count("\n") + 1)


def preflight(root):
    tests = (root / "tests/runtime_darwin.zig").read_text()
    for control in CONTROLS:
        unique((root / control.path).read_text(), control.old)
        assertion_lines(tests, control)
        unique(tests, f'test "{control.test}" {{')
