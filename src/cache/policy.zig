const wire = @import("../wire.zig");
const config = @import("../config.zig");

pub const Policy = struct {
    bank: enum { positive, denial },
    lifetime_s: u32,
    category: enum { answer, failure },
};

/// Parsed, validated upstream messages only. Incomplete/error answers are not positives.
pub fn classify(
    packet: *const wire.Packet,
    settings: *const config.Cache,
    question_kind: u16,
) ?Policy {
    if (!packet.header.has(.response)) return null;
    if (packet.header.has(.truncated)) return null;
    if (packet.opt) |index| {
        if (packet.records[index].ttl_s >> 24 != 0) return null;
    }
    const rcode = packet.header.bits & 15;
    if (rcode == 2) return .{ .bank = .denial, .lifetime_s = 5, .category = .failure };
    if (rcode != 0) {
        if (rcode != 3) return null;
    }
    var denial_s: ?u32 = null;
    var terminal: u16 = 0;
    var positive_s: u32 = settings.max_ttl_s;
    for (packet.records[0..packet.record_count]) |*record| {
        if (record.kind == 41) continue;
        positive_s = @min(positive_s, clamp(record.ttl_s, settings));
        if (record.section == .answer) {
            if (terminalAnswer(record.kind, question_kind)) terminal += 1;
        }
        if (record.section != .authority) continue;
        if (record.kind != 6) continue;
        // The codec validates the SOA layout; MINIMUM is its final u32 (RFC 1035 §3.3.13).
        const minimum_s = wire.integer(u32, packet.bytes[record.data_end - 4 .. record.data_end]);
        const lifetime_s = @min(record.ttl_s, minimum_s);
        denial_s = @min(denial_s orelse lifetime_s, lifetime_s);
    }
    if (rcode == 3) return denial(denial_s, settings);
    if (packet.header.counts[1] == 0) return denial(denial_s, settings);
    if (terminal == 0) {
        if (denial_s != null) return denial(denial_s, settings);
    }
    return .{ .bank = .positive, .lifetime_s = positive_s, .category = .answer };
}

fn terminalAnswer(record_kind: u16, question_kind: u16) bool {
    if (record_kind == question_kind) return true;
    if (question_kind == 255) return true;
    if (record_kind == 5) return false;
    if (record_kind == 39) return false;
    if (record_kind == 46) return false;
    return true;
}

fn denial(lifetime_s: ?u32, settings: *const config.Cache) ?Policy {
    // RFC 2308 §5: without an SOA there is no reusable denial lifetime.
    const seconds = lifetime_s orelse return null;
    return .{
        .bank = .denial,
        .lifetime_s = @max(5, @min(seconds, settings.denialMaximum())),
        .category = .answer,
    };
}

fn clamp(ttl_s: u32, settings: *const config.Cache) u32 {
    return @max(settings.min_ttl_s, @min(ttl_s, settings.max_ttl_s));
}

pub fn apply(packet: *wire.Packet, policy: *const Policy, settings: *const config.Cache) void {
    for (packet.records[0..packet.record_count]) |*record| {
        if (record.kind == 41) continue;
        record.ttl_s = switch (policy.bank) {
            .positive => clamp(record.ttl_s, settings),
            .denial => policy.lifetime_s,
        };
    }
}
