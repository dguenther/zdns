const flags = @import("flags");
const xev = @import("xev");
const std = @import("std");

const http = @import("http.zig");
const util = @import("util.zig");

/// Type of blocking action to take for blocked domains
pub const BlockMode = enum {
    /// Return an NXDOMAIN response (domain does not exist)
    nxdomain,

    /// Return a null response (resolve to 0.0.0.0)
    nullip,

    pub const descriptions = .{
        .nxdomain = "Return an NXDOMAIN response (domain does not exist)",
        .nullip = "Return a null response (resolve to 0.0.0.0)",
    };

    /// Parse block mode from string
    pub fn fromString(str: []const u8) !BlockMode {
        if (std.mem.eql(u8, str, "nxdomain")) {
            return .nxdomain;
        } else if (std.mem.eql(u8, str, "nullip")) {
            return .nullip;
        } else {
            return error.InvalidBlockMode;
        }
    }
};

const Flags = struct {
    pub const description =
        \\A DNS forwarding server that uses a blocklist to filter DNS requests.
    ;

    pub const descriptions = .{ .@"blocklist-url" = "URL to the blocklist file (required, e.g., https://some-site.com/hosts.txt)", .address = "Local address to bind to (defaults to 0.0.0.0)", .port = "Local port to bind to (defaults to 53)", .@"block-mode" = "Response to return for filtered addresses (defaults to nullip)" };

    @"blocklist-url": []const u8,
    address: []const u8 = "0.0.0.0",
    port: u16 = 53,
    @"block-mode": BlockMode = .nullip,

    // The 'positional' field is a special field that defines arguments that are not associated
    // with any --flag. Hence the name "positional" arguments.
    positional: struct {
        upstream: []const u8,

        pub const descriptions = .{
            .upstream = "IPv4 upstream DNS server to forward requests to (required)",
        };
    },

    // Optional declaration to define shorthands. These can be chained e.g '-fs large'.
    pub const switches = .{
        .@"blocklist-url" = 'b',
        .address = 'a',
        .port = 'p',
    };
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer if (gpa.deinit() == std.heap.Check.leak) {
        std.log.err("Memory leak detected", .{});
    };

    const args = try std.process.argsAlloc(gpa.allocator());
    defer std.process.argsFree(gpa.allocator(), args);

    const options = flags.parseOrExit(args, "zdns", Flags, .{});

    std.log.info("Using block mode: {s}", .{@tagName(options.@"block-mode")});

    var blocked_domains_map = std.StringHashMap([]const u8).init(gpa.allocator());
    try http.requestHostsFile(options.@"blocklist-url", &blocked_domains_map, gpa.allocator());

    var thread_pool = xev.ThreadPool.init(.{});
    defer thread_pool.deinit();
    defer thread_pool.shutdown();

    var loop = try xev.Loop.init(.{
        .thread_pool = &thread_pool,
    });
    defer loop.deinit();

    const upstream_addr = try std.net.Address.parseIp4(options.positional.upstream, 53);

    const addr = try std.net.Address.parseIp4(options.address, options.port);
    var server = try ForwardingServer.init(addr, upstream_addr, gpa.allocator(), options.@"block-mode", blocked_domains_map);

    defer server.deinit();

    try server.start(&loop);

    std.log.info("DNS forwarder listening on {}", .{addr});

    try loop.run(.until_done);
}

const max_send_slots = 256;
const max_udp_payload_len = 512;
const max_canonical_qname_len = 255;
const max_in_flight_requests = 4_096;
const max_request_id_allocation_attempts = 4_096;
const request_id_space = std.math.maxInt(u16) + 1;
const request_timeout_ns = 5 * std.time.ns_per_s;
/// Quarantining every completed/expired ID for this long caps sustained
/// throughput at ~13k qps (65536 IDs / 5s); past that, ID allocation fails
/// and new queries are answered with SERVFAIL until the quarantine drains.
const expired_request_id_quarantine_ns = request_timeout_ns;
const request_cleanup_interval_ms = 1_000;
const dns_header_len = 12;
const dns_flag_qr = 0x8000;
const dns_rcode_noerror = 0;
const dns_rcode_servfail = 2;
const dns_rcode_nxdomain = 3;

const ActiveRequest = struct {
    client_addr: std.net.Address,
    client_id: u16,
    canonical_qname: [max_canonical_qname_len]u8 = undefined,
    canonical_qname_len: u8,
    qtype: u16,
    qclass: u16,
    upstream_addr: std.net.Address,
    expires_at_ns: u64,

    fn init(client_addr: std.net.Address, client_id: u16, question: util.DnsQuestion, upstream_addr: std.net.Address, expires_at_ns: u64) !ActiveRequest {
        if (question.canonical_qname.len > max_canonical_qname_len) return error.DomainNameTooLong;

        var request = ActiveRequest{
            .client_addr = client_addr,
            .client_id = client_id,
            .canonical_qname_len = @intCast(question.canonical_qname.len),
            .qtype = question.qtype,
            .qclass = question.qclass,
            .upstream_addr = upstream_addr,
            .expires_at_ns = expires_at_ns,
        };
        @memcpy(request.canonical_qname[0..question.canonical_qname.len], question.canonical_qname);
        return request;
    }

    fn canonicalQnameSlice(self: *const ActiveRequest) []const u8 {
        return self.canonical_qname[0..self.canonical_qname_len];
    }
};

const ActiveRequestMap = std.AutoHashMap(u16, ActiveRequest);

/// Upstream IDs whose query may have reached the wire (answered or expired
/// requests) are quarantined here until the stored deadline so a late
/// upstream response cannot be matched against a new request reusing the ID.
/// An ID may be removed from the active map without quarantine only when its
/// send failed before anything was queued (xev.UDP.write cannot fail after
/// queueing).
const RetiredRequestIdMap = std.AutoHashMap(u16, u64);

const RequestIdAllocator = struct {
    random: std.Random = std.crypto.random,
    max_attempts: usize = max_request_id_allocation_attempts,

    fn next(self: *RequestIdAllocator, request_map: *const ActiveRequestMap, retired_request_ids: *const RetiredRequestIdMap, now_ns: u64) !u16 {
        for (0..self.max_attempts) |_| {
            const id = self.random.int(u16);

            if (request_map.contains(id)) continue;
            if (retired_request_ids.get(id)) |retired_until_ns| {
                if (retired_until_ns > now_ns) continue;
            }

            return id;
        }

        return error.NoAvailableRequestIds;
    }
};

const SendDirection = enum {
    upstream,
    local,

    fn label(self: SendDirection) []const u8 {
        return switch (self) {
            .upstream => "upstm",
            .local => "local",
        };
    }
};

const SendSlot = struct {
    completion: xev.Completion = undefined,
    state: xev.UDP.State = undefined,
    buffer: [max_udp_payload_len]u8 = undefined,
    len: usize = 0,
    addr: std.net.Address = undefined,
    direction: SendDirection = .local,
    in_use: bool = false,

    fn release(self: *SendSlot) void {
        self.in_use = false;
    }
};

const SendPool = struct {
    slots: [max_send_slots]SendSlot = [_]SendSlot{.{}} ** max_send_slots,
    next_slot: usize = 0,

    fn acquire(self: *SendPool, direction: SendDirection, addr: std.net.Address, data: []const u8) !*SendSlot {
        if (data.len > max_udp_payload_len) return error.BufferTooSmall;

        for (0..self.slots.len) |offset| {
            const index = (self.next_slot + offset) % self.slots.len;
            const slot = &self.slots[index];
            if (slot.in_use) continue;

            slot.len = data.len;
            slot.addr = addr;
            slot.direction = direction;
            @memcpy(slot.buffer[0..data.len], data);
            slot.in_use = true;
            self.next_slot = (index + 1) % self.slots.len;
            return slot;
        }

        return error.NoSendSlots;
    }
};

fn sendUdp(
    udp: *xev.UDP,
    pool: *SendPool,
    loop: *xev.Loop,
    direction: SendDirection,
    addr: std.net.Address,
    data: []const u8,
) !void {
    const slot = try pool.acquire(direction, addr, data);
    udp.write(loop, &slot.completion, &slot.state, addr, .{ .slice = slot.buffer[0..slot.len] }, SendSlot, slot, sendUdpCallback);
}

fn sendUdpCallback(
    slot: ?*SendSlot,
    _: *xev.Loop,
    _: *xev.Completion,
    _: *xev.UDP.State,
    _: xev.UDP,
    _: xev.WriteBuffer,
    r: xev.WriteError!usize,
) xev.CallbackAction {
    const send_slot = slot.?;
    defer send_slot.release();

    const n = r catch |err| {
        std.log.warn("err={}", .{err});
        return .disarm;
    };

    std.log.debug("send - {s} - {d} bytes ({})", .{ send_slot.direction.label(), n, send_slot.addr });

    return .disarm;
}

const PacketWriter = struct {
    buffer: []u8,
    pos: usize,

    fn writeByte(self: *PacketWriter, value: u8) !void {
        if (self.pos + 1 > self.buffer.len) return error.BufferTooSmall;
        self.buffer[self.pos] = value;
        self.pos += 1;
    }

    fn writeU16(self: *PacketWriter, value: u16) !void {
        if (self.pos + 2 > self.buffer.len) return error.BufferTooSmall;
        std.mem.writeInt(u16, self.buffer[self.pos..][0..2], value, .big);
        self.pos += 2;
    }

    fn writeU32(self: *PacketWriter, value: u32) !void {
        if (self.pos + 4 > self.buffer.len) return error.BufferTooSmall;
        std.mem.writeInt(u32, self.buffer[self.pos..][0..4], value, .big);
        self.pos += 4;
    }

    fn writeZeroes(self: *PacketWriter, len: usize) !void {
        if (self.pos + len > self.buffer.len) return error.BufferTooSmall;
        @memset(self.buffer[self.pos .. self.pos + len], 0);
        self.pos += len;
    }
};

/// Copies the request through the question section and stamps it as an
/// answerless response with the given RCODE. Returns the header+question
/// slice; callers may append records and adjust the counts afterwards.
fn writeResponseHeader(buffer: []u8, request: []const u8, question: util.DnsQuestion, rcode: u8) ![]u8 {
    if (question.question_end > request.len or question.question_end > buffer.len) return error.PacketTooShort;

    @memcpy(buffer[0..question.question_end], request[0..question.question_end]);

    buffer[2] = buffer[2] | 0x80; // QR
    buffer[3] = (buffer[3] & 0xF0) | rcode;
    std.mem.writeInt(u16, buffer[6..][0..2], 0, .big); // ANCOUNT
    std.mem.writeInt(u16, buffer[8..][0..2], 0, .big); // NSCOUNT
    std.mem.writeInt(u16, buffer[10..][0..2], 0, .big); // ARCOUNT

    return buffer[0..question.question_end];
}

fn buildBlockedResponse(buffer: []u8, request: []const u8, question: util.DnsQuestion, block_mode: BlockMode) ![]u8 {
    switch (block_mode) {
        .nxdomain => return writeResponseHeader(buffer, request, question, dns_rcode_nxdomain),
        .nullip => {
            const header = try writeResponseHeader(buffer, request, question, dns_rcode_noerror);

            const rdata_len: usize = switch (question.qtype) {
                1 => 4, // A
                28 => 16, // AAAA
                else => 0,
            };

            if (question.qclass != 1 or rdata_len == 0) {
                return header;
            }

            std.mem.writeInt(u16, buffer[6..][0..2], 1, .big); // ANCOUNT

            var writer = PacketWriter{ .buffer = buffer, .pos = question.question_end };
            try writer.writeU16(0xC00C); // Pointer to offset 12 (start of question)
            try writer.writeU16(question.qtype);
            try writer.writeU16(question.qclass);
            try writer.writeU32(60);
            try writer.writeU16(@intCast(rdata_len));
            try writer.writeZeroes(rdata_len);

            return buffer[0..writer.pos];
        },
    }
}

fn validateUpstreamResponse(request_map: *ActiveRequestMap, sender: std.net.Address, response: []const u8) !ActiveRequestMap.Entry {
    if (response.len < dns_header_len) return error.PacketTooShort;

    const response_flags = std.mem.readInt(u16, response[2..][0..2], .big);
    if ((response_flags & dns_flag_qr) == 0) return error.NotUpstreamResponse;

    const upstream_request_id = std.mem.readInt(u16, response[0..2], .big);
    const entry = request_map.getEntry(upstream_request_id) orelse return error.UnknownRequestId;
    const request = entry.value_ptr;

    if (!sender.eql(request.upstream_addr)) return error.UnexpectedUpstreamSender;

    // Questionless responses (header-only upstream failures, possibly with
    // an EDNS OPT record) carry no question to cross-check; ID, sender, and
    // the QR bit are all we can validate.
    const qdcount = std.mem.readInt(u16, response[4..][0..2], .big);
    if (qdcount == 0) return entry;
    if (qdcount != 1) return error.UnexpectedQuestionCount;

    var domain_buffer: [256]u8 = undefined;
    const question = try util.parseDnsQuestion(&domain_buffer, response);
    // DNS names compare case-insensitively; pass response casing through and
    // leave DNS 0x20 validation to clients that require it.
    if (!std.mem.eql(u8, question.canonical_qname, request.canonicalQnameSlice()) or
        question.qtype != request.qtype or
        question.qclass != request.qclass)
    {
        return error.QuestionMismatch;
    }

    return entry;
}

const PreparedUpstreamResponse = struct {
    client_addr: std.net.Address,
    upstream_id: u16,
};

fn prepareUpstreamResponse(request_map: *ActiveRequestMap, sender: std.net.Address, response: []u8) !PreparedUpstreamResponse {
    const entry = try validateUpstreamResponse(request_map, sender, response);

    const prepared = PreparedUpstreamResponse{
        .client_addr = entry.value_ptr.client_addr,
        .upstream_id = entry.key_ptr.*,
    };

    std.mem.writeInt(u16, response[0..2], entry.value_ptr.client_id, .big);
    return prepared;
}

fn completeUpstreamRequest(request_map: *ActiveRequestMap, upstream_request_id: u16) void {
    _ = request_map.remove(upstream_request_id);
}

fn cleanupExpiredRequests(request_map: *ActiveRequestMap, retired_request_ids: *RetiredRequestIdMap, now_ns: u64) usize {
    // The map never exceeds max_in_flight_requests (enforced on insert), so
    // one pass over a stack buffer always collects every expired entry.
    var expired_ids: [max_in_flight_requests]u16 = undefined;
    var expired_count: usize = 0;

    var it = request_map.iterator();
    while (it.next()) |entry| {
        if (entry.value_ptr.expires_at_ns <= now_ns) {
            expired_ids[expired_count] = entry.key_ptr.*;
            expired_count += 1;
        }
    }

    for (expired_ids[0..expired_count]) |id| {
        _ = request_map.remove(id);
        retired_request_ids.putAssumeCapacity(id, now_ns + expired_request_id_quarantine_ns);
    }

    return expired_count;
}

fn cleanupRetiredRequestIds(retired_request_ids: *RetiredRequestIdMap, now_ns: u64) usize {
    // The quarantine map can hold up to the full ID space; remove expired
    // entries in bounded batches and let leftovers drain on later ticks
    // (an ID staying quarantined a little longer is harmless).
    var expired_ids: [max_in_flight_requests]u16 = undefined;
    var expired_count: usize = 0;

    var it = retired_request_ids.iterator();
    while (it.next()) |entry| {
        if (entry.value_ptr.* <= now_ns) {
            expired_ids[expired_count] = entry.key_ptr.*;
            expired_count += 1;
            if (expired_count == expired_ids.len) break;
        }
    }

    for (expired_ids[0..expired_count]) |id| {
        _ = retired_request_ids.remove(id);
    }

    return expired_count;
}

const ForwardingServer = struct {
    upstream_server: UpstreamServer,
    local_server: LocalServer,
    request_map: ActiveRequestMap,
    retired_request_ids: RetiredRequestIdMap,
    request_id_allocator: RequestIdAllocator,
    blocked_domains: std.StringHashMap([]const u8),
    block_mode: BlockMode,
    cleanup_timer: xev.Timer,
    cleanup_completion: xev.Completion = .{},
    monotonic_timer: std.time.Timer,

    pub fn init(local_addr: std.net.Address, upstream_addr: std.net.Address, alloc: std.mem.Allocator, block_mode_param: BlockMode, blocked_domains_param: std.StringHashMap([]const u8)) !ForwardingServer {
        var request_map = ActiveRequestMap.init(alloc);
        errdefer request_map.deinit();
        try request_map.ensureTotalCapacity(max_in_flight_requests);

        var retired_request_ids = RetiredRequestIdMap.init(alloc);
        errdefer retired_request_ids.deinit();
        // Reserve the full 16-bit ID space (~1 MB) so quarantine inserts can
        // never fail: an ID removed from the active map must always land in
        // quarantine, or a late upstream response could match a new request
        // that reuses the ID.
        try retired_request_ids.ensureTotalCapacity(request_id_space);

        const cleanup_timer = try xev.Timer.init();
        errdefer cleanup_timer.deinit();

        return .{
            .upstream_server = try UpstreamServer.init(upstream_addr),
            .local_server = try LocalServer.init(local_addr),
            .request_map = request_map,
            .retired_request_ids = retired_request_ids,
            .request_id_allocator = .{},
            .blocked_domains = blocked_domains_param,
            .block_mode = block_mode_param,
            .cleanup_timer = cleanup_timer,
            .monotonic_timer = try std.time.Timer.start(),
        };
    }

    pub fn deinit(self: *ForwardingServer) void {
        var it = self.blocked_domains.iterator();
        while (it.next()) |entry| {
            self.blocked_domains.allocator.free(entry.key_ptr.*);
        }
        self.blocked_domains.deinit();
        self.request_map.deinit();
        self.retired_request_ids.deinit();
        self.cleanup_timer.deinit();
    }

    pub fn start(self: *ForwardingServer, loop: *xev.Loop) !void {
        try self.upstream_server.start(loop, ForwardingServer, self, ForwardingServer.upstreamReadCallback);
        try self.local_server.start(loop, ForwardingServer, self, ForwardingServer.localReadCallback);
        self.cleanup_timer.run(loop, &self.cleanup_completion, request_cleanup_interval_ms, ForwardingServer, self, ForwardingServer.cleanupCallback);
    }

    fn sendServfail(self: *ForwardingServer, loop: *xev.Loop, client_addr: std.net.Address, request: []const u8, question: util.DnsQuestion) void {
        var response_buffer: [512]u8 = undefined;
        const response = writeResponseHeader(&response_buffer, request, question, dns_rcode_servfail) catch |err| {
            std.log.warn("Failed to build SERVFAIL response: {}", .{err});
            return;
        };

        self.local_server.sendTo(loop, client_addr, response) catch |err| {
            std.log.warn("Failed to send SERVFAIL response: {}", .{err});
        };
    }

    fn cleanupCallback(
        self: ?*ForwardingServer,
        loop: *xev.Loop,
        completion: *xev.Completion,
        result: xev.Timer.RunError!void,
    ) xev.CallbackAction {
        const server = self.?;
        cleanup: {
            result catch |err| {
                switch (err) {
                    error.Canceled => return .disarm,
                    else => std.log.warn("Request cleanup timer failed: {}", .{err}),
                }
                break :cleanup;
            };

            const now_ns = server.monotonic_timer.read();
            const retired_removed = cleanupRetiredRequestIds(&server.retired_request_ids, now_ns);
            const expired_removed = cleanupExpiredRequests(&server.request_map, &server.retired_request_ids, now_ns);
            if (expired_removed > 0 or retired_removed > 0) {
                std.log.debug("Cleaned up {d} expired upstream requests and {d} retired request IDs", .{ expired_removed, retired_removed });
            }
        }

        server.cleanup_timer.run(loop, completion, request_cleanup_interval_ms, ForwardingServer, server, ForwardingServer.cleanupCallback);
        return .disarm;
    }

    fn upstreamReadCallback(
        self: ?*ForwardingServer,
        loop: *xev.Loop,
        _: *xev.Completion,
        _: *xev.UDP.State,
        sender: std.net.Address,
        _: xev.UDP,
        rbuf: xev.ReadBuffer,
        rsize: xev.ReadError!usize,
    ) xev.CallbackAction {
        const n = rsize catch |err| {
            switch (err) {
                error.EOF => {},
                else => std.log.warn("err={}", .{err}),
            }

            return .disarm;
        };

        const data = rbuf.slice[0..n];

        std.log.debug("recv - upstm - {d} bytes ({})", .{ n, sender });

        const prepared = prepareUpstreamResponse(&self.?.request_map, sender, data) catch |err| {
            std.log.warn("Dropping invalid upstream response from {}: {}", .{ sender, err });
            return .rearm;
        };

        // The response settles the request either way: retire the ID before
        // attempting delivery so a send failure can't leave it active.
        completeUpstreamRequest(&self.?.request_map, prepared.upstream_id);
        self.?.retired_request_ids.putAssumeCapacity(prepared.upstream_id, self.?.monotonic_timer.read() + expired_request_id_quarantine_ns);

        self.?.local_server.sendTo(loop, prepared.client_addr, data) catch |err| {
            std.log.warn("Failed to send upstream response to client: {}", .{err});
        };

        return .rearm;
    }

    fn localReadCallback(
        self: ?*ForwardingServer,
        loop: *xev.Loop,
        _: *xev.Completion,
        _: *xev.UDP.State,
        sender: std.net.Address,
        _: xev.UDP,
        rbuf: xev.ReadBuffer,
        rsize: xev.ReadError!usize,
    ) xev.CallbackAction {
        const n = rsize catch |err| {
            switch (err) {
                error.EOF => {},
                else => std.log.warn("err={}", .{err}),
            }

            return .disarm;
        };

        const data = rbuf.slice[0..n];
        if (data.len < 2) {
            std.log.warn("Local request too short: {d} bytes", .{data.len});
            return .rearm;
        }

        // parse the request ID from the response
        const client_request_id = std.mem.readInt(u16, data[0..2], .big);

        std.log.debug("recv - local - id: {d} - {d} bytes from {}", .{ client_request_id, n, sender });

        var domain_buffer: [256]u8 = undefined;
        const question = util.parseDnsQuestion(&domain_buffer, data) catch |err| {
            std.log.warn("Failed to parse DNS question: {}\n", .{err});
            return .rearm;
        };

        if (comptime std.log.defaultLogEnabled(.info)) {
            var qtype_buffer: [5]u8 = undefined;
            var qclass_buffer: [5]u8 = undefined;
            const qtype_display = util.qtypeDisplay(question.qtype, &qtype_buffer);
            const qclass_display = util.qclassDisplay(question.qclass, &qclass_buffer);

            std.log.info("DNS query: qname={s} qtype={s} qclass={s}", .{ question.canonical_qname, qtype_display, qclass_display });
        }

        // Check if domain is blocked
        if (self.?.blocked_domains.contains(question.canonical_qname)) {
            std.log.info("Blocking domain: {s}", .{question.canonical_qname});

            var response_buffer: [512]u8 = undefined;
            const response = buildBlockedResponse(&response_buffer, data, question, self.?.block_mode) catch |err| {
                std.log.warn("Failed to build blocked response: {}\n", .{err});
                return .rearm;
            };

            self.?.local_server.sendTo(loop, sender, response) catch |err| {
                std.log.warn("Failed to send blocked response: {}\n", .{err});
            };

            return .rearm;
        }

        // TODO: Try expiring stale requests before dropping a new request at the in-flight limit.
        if (self.?.request_map.count() >= max_in_flight_requests) {
            std.log.warn("Too many in-flight upstream requests", .{});
            self.?.sendServfail(loop, sender, data, question);
            return .rearm;
        }

        const now_ns = self.?.monotonic_timer.read();
        const upstream_request_id = self.?.request_id_allocator.next(&self.?.request_map, &self.?.retired_request_ids, now_ns) catch |err| {
            std.log.warn("No available upstream request IDs: {}", .{err});
            self.?.sendServfail(loop, sender, data, question);
            return .rearm;
        };

        const active_request = ActiveRequest.init(
            sender,
            client_request_id,
            question,
            self.?.upstream_server.addr,
            now_ns + request_timeout_ns,
        ) catch |err| {
            std.log.warn("Failed to track upstream request: {}", .{err});
            self.?.sendServfail(loop, sender, data, question);
            return .rearm;
        };

        self.?.request_map.put(upstream_request_id, active_request) catch |err| {
            std.log.warn("Failed to put request ID {}: {}", .{ upstream_request_id, err });
            self.?.sendServfail(loop, sender, data, question);
            return .rearm;
        };

        std.mem.writeInt(u16, data[0..2], upstream_request_id, .big);
        self.?.upstream_server.send(loop, data) catch |err| {
            _ = self.?.request_map.remove(upstream_request_id);
            std.log.warn("Failed to send request upstream: {}", .{err});
            std.mem.writeInt(u16, data[0..2], client_request_id, .big);
            self.?.sendServfail(loop, sender, data, question);
        };

        return .rearm;
    }
};

const UpstreamServer = struct {
    udp: xev.UDP,
    addr: std.net.Address,
    udp_recv_state: xev.UDP.State = undefined,
    c_recv: xev.Completion = undefined,
    recv_buf: [512]u8 = undefined,
    send_pool: SendPool = .{},

    pub fn init(addr: std.net.Address) !UpstreamServer {
        return .{
            .udp = try xev.UDP.init(addr),
            .addr = addr,
        };
    }

    pub fn start(self: *UpstreamServer, loop: *xev.Loop, comptime Userdata: type, userdata: ?*Userdata, comptime cb: *const fn (
        ud: ?*Userdata,
        l: *xev.Loop,
        c: *xev.Completion,
        s: *xev.UDP.State,
        addr: std.net.Address,
        s: xev.UDP,
        b: xev.ReadBuffer,
        r: xev.ReadError!usize,
    ) xev.CallbackAction) !void {
        self.udp.read(
            loop,
            &self.c_recv,
            &self.udp_recv_state,
            .{ .slice = &self.recv_buf },
            Userdata,
            userdata,
            cb,
        );
    }

    pub fn send(self: *UpstreamServer, loop: *xev.Loop, data: []const u8) !void {
        // TODO: Implement a basic cache

        try sendUdp(&self.udp, &self.send_pool, loop, .upstream, self.addr, data);
    }
};

const LocalServer = struct {
    udp: xev.UDP,
    addr: std.net.Address,
    udp_recv_state: xev.UDP.State = undefined,
    c_recv: xev.Completion = undefined,
    recv_buf: [512]u8 = undefined,
    send_pool: SendPool = .{},

    pub fn init(addr: std.net.Address) !LocalServer {
        return .{
            .udp = try xev.UDP.init(addr),
            .addr = addr,
        };
    }

    pub fn start(self: *LocalServer, loop: *xev.Loop, comptime Userdata: type, userdata: ?*Userdata, comptime cb: *const fn (
        ud: ?*Userdata,
        l: *xev.Loop,
        c: *xev.Completion,
        s: *xev.UDP.State,
        addr: std.net.Address,
        s: xev.UDP,
        b: xev.ReadBuffer,
        r: xev.ReadError!usize,
    ) xev.CallbackAction) !void {
        try self.udp.bind(self.addr);

        self.udp.read(
            loop,
            &self.c_recv,
            &self.udp_recv_state,
            .{ .slice = &self.recv_buf },
            Userdata,
            userdata,
            cb,
        );
    }

    fn sendTo(self: *LocalServer, loop: *xev.Loop, addr: std.net.Address, data: []const u8) !void {
        try sendUdp(&self.udp, &self.send_pool, loop, .local, addr, data);
    }
};

test "blocked nullip response returns A 0.0.0.0 for A queries" {
    var request = try bytesFromHex("cfc9010000010000000000000a6475636b6475636b676f03636f6d0000010001");

    var domain_buffer: [256]u8 = undefined;
    const question = try util.parseDnsQuestion(&domain_buffer, &request);

    var response_buffer: [512]u8 = undefined;
    const response = try buildBlockedResponse(&response_buffer, &request, question, .nullip);

    try std.testing.expectEqual(@as(usize, question.question_end + 16), response.len);
    try std.testing.expect(response[2] & 0x80 != 0);
    try std.testing.expectEqual(@as(u8, 0), response[3] & 0x0F);
    try std.testing.expectEqual(@as(u8, 0), response[6]);
    try std.testing.expectEqual(@as(u8, 1), response[7]);

    const answer = [_]u8{
        0xC0, 0x0C, // name pointer
        0x00, 0x01, // A
        0x00, 0x01, // IN
        0x00, 0x00, 0x00, 0x3C, // TTL
        0x00, 0x04, // RDLENGTH
        0x00, 0x00, 0x00, 0x00, // 0.0.0.0
    };
    try std.testing.expectEqualSlices(u8, &answer, response[question.question_end..]);
}

test "SERVFAIL response preserves the request ID and question" {
    var request = try bytesFromHex("cfc9010000010000000000000a6475636b6475636b676f03636f6d0000010001");
    var domain_buffer: [256]u8 = undefined;
    const question = try util.parseDnsQuestion(&domain_buffer, &request);

    var response_buffer: [512]u8 = undefined;
    const response = try writeResponseHeader(&response_buffer, &request, question, dns_rcode_servfail);

    try std.testing.expectEqual(question.question_end, response.len);
    try std.testing.expectEqual(@as(u16, 0xcfc9), std.mem.readInt(u16, response[0..2], .big));
    try std.testing.expect(response[2] & 0x80 != 0);
    try std.testing.expectEqual(@as(u8, dns_rcode_servfail), response[3] & 0x0F);
    try std.testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, response[4..6], .big));
    try std.testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, response[6..8], .big));
    try std.testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, response[8..10], .big));
    try std.testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, response[10..12], .big));
    try std.testing.expectEqualSlices(u8, request[12..question.question_end], response[12..]);
}

const SequenceRandom = struct {
    values: []const u16,
    index: usize = 0,

    fn random(self: *SequenceRandom) std.Random {
        return std.Random.init(self, SequenceRandom.fill);
    }

    fn fill(self: *SequenceRandom, buffer: []u8) void {
        std.debug.assert(buffer.len == 2);
        std.debug.assert(self.index < self.values.len);
        std.mem.writeInt(u16, buffer[0..2], self.values[self.index], .little);
        self.index += 1;
    }
};

fn bytesFromHex(comptime hex_string: []const u8) ![hex_string.len / 2]u8 {
    var bytes: [hex_string.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, hex_string);
    return bytes;
}

fn makeActiveRequest(client_id: u16, client_addr: std.net.Address, upstream_addr: std.net.Address, request: []const u8, expires_at_ns: u64) !ActiveRequest {
    var domain_buffer: [256]u8 = undefined;
    const question = try util.parseDnsQuestion(&domain_buffer, request);
    return ActiveRequest.init(client_addr, client_id, question, upstream_addr, expires_at_ns);
}

fn makeHeaderOnlyResponse(upstream_id: u16, response_flags: u16) [dns_header_len]u8 {
    var response = [_]u8{0} ** dns_header_len;
    std.mem.writeInt(u16, response[0..2], upstream_id, .big);
    std.mem.writeInt(u16, response[2..4], response_flags, .big);
    return response;
}

test "request ID allocator skips in-flight IDs" {
    var request_map = ActiveRequestMap.init(std.testing.allocator);
    defer request_map.deinit();
    var retired_request_ids = RetiredRequestIdMap.init(std.testing.allocator);
    defer retired_request_ids.deinit();

    var request = try bytesFromHex("cfc9010000010000000000000a6475636b6475636b676f03636f6d0000010001");
    const client_addr = try std.net.Address.parseIp4("127.0.0.1", 1234);
    const upstream_addr = try std.net.Address.parseIp4("9.9.9.9", 53);
    try request_map.put(10, try makeActiveRequest(100, client_addr, upstream_addr, &request, 1_000));
    try request_map.put(11, try makeActiveRequest(101, client_addr, upstream_addr, &request, 1_000));

    var sequence = SequenceRandom{ .values = &.{ 10, 11, 12 } };
    var allocator = RequestIdAllocator{ .random = sequence.random(), .max_attempts = 3 };
    try std.testing.expectEqual(@as(u16, 12), try allocator.next(&request_map, &retired_request_ids, 500));
    try std.testing.expectEqual(@as(usize, 3), sequence.index);
}

test "request ID allocator returns failure when retry attempts collide" {
    var request_map = ActiveRequestMap.init(std.testing.allocator);
    defer request_map.deinit();
    var retired_request_ids = RetiredRequestIdMap.init(std.testing.allocator);
    defer retired_request_ids.deinit();

    var request = try bytesFromHex("cfc9010000010000000000000a6475636b6475636b676f03636f6d0000010001");
    const client_addr = try std.net.Address.parseIp4("127.0.0.1", 1234);
    const upstream_addr = try std.net.Address.parseIp4("9.9.9.9", 53);
    try request_map.put(42, try makeActiveRequest(100, client_addr, upstream_addr, &request, 1_000));

    var sequence = SequenceRandom{ .values = &.{ 42, 42, 42 } };
    var allocator = RequestIdAllocator{ .random = sequence.random(), .max_attempts = 3 };
    try std.testing.expectError(error.NoAvailableRequestIds, allocator.next(&request_map, &retired_request_ids, 500));
    try std.testing.expectEqual(@as(usize, 3), sequence.index);
}

test "request ID allocator skips retired IDs still in quarantine" {
    var request_map = ActiveRequestMap.init(std.testing.allocator);
    defer request_map.deinit();
    var retired_request_ids = RetiredRequestIdMap.init(std.testing.allocator);
    defer retired_request_ids.deinit();
    try retired_request_ids.put(12, 1_000);

    var sequence = SequenceRandom{ .values = &.{ 12, 13 } };
    var allocator = RequestIdAllocator{ .random = sequence.random(), .max_attempts = 2 };
    try std.testing.expectEqual(@as(u16, 13), try allocator.next(&request_map, &retired_request_ids, 500));
    try std.testing.expectEqual(@as(usize, 2), sequence.index);
}

test "request ID allocator allows retired IDs after quarantine expires" {
    var request_map = ActiveRequestMap.init(std.testing.allocator);
    defer request_map.deinit();
    var retired_request_ids = RetiredRequestIdMap.init(std.testing.allocator);
    defer retired_request_ids.deinit();
    try retired_request_ids.put(12, 1_000);

    var sequence = SequenceRandom{ .values = &.{12} };
    var allocator = RequestIdAllocator{ .random = sequence.random(), .max_attempts = 1 };
    try std.testing.expectEqual(@as(u16, 12), try allocator.next(&request_map, &retired_request_ids, 1_000));
    try std.testing.expectEqual(@as(usize, 1), sequence.index);
}

test "upstream response validation rejects matching ID with wrong qname" {
    var request_map = ActiveRequestMap.init(std.testing.allocator);
    defer request_map.deinit();

    var original_request = try bytesFromHex("cfc9010000010000000000000a6475636b6475636b676f03636f6d0000010001");
    var response = try bytesFromHex("123481800001000000000000076578616d706c6503636f6d0000010001");
    const client_addr = try std.net.Address.parseIp4("127.0.0.1", 1234);
    const upstream_addr = try std.net.Address.parseIp4("9.9.9.9", 53);
    try request_map.put(0x1234, try makeActiveRequest(0xcfc9, client_addr, upstream_addr, &original_request, 1_000));

    try std.testing.expectError(error.QuestionMismatch, prepareUpstreamResponse(&request_map, upstream_addr, &response));
    try std.testing.expectEqual(@as(u32, 1), request_map.count());
}

test "upstream response validation rejects matching ID with wrong qtype and qclass" {
    var request_map = ActiveRequestMap.init(std.testing.allocator);
    defer request_map.deinit();

    var original_request = try bytesFromHex("cfc9010000010000000000000a6475636b6475636b676f03636f6d0000010001");
    var response = try bytesFromHex("1234818000010000000000000a6475636b6475636b676f03636f6d0000010001");
    const client_addr = try std.net.Address.parseIp4("127.0.0.1", 1234);
    const upstream_addr = try std.net.Address.parseIp4("9.9.9.9", 53);
    try request_map.put(0x1234, try makeActiveRequest(0xcfc9, client_addr, upstream_addr, &original_request, 1_000));

    var domain_buffer: [256]u8 = undefined;
    const question = try util.parseDnsQuestion(&domain_buffer, &response);
    std.mem.writeInt(u16, response[question.question_end - 4 ..][0..2], 28, .big);
    std.mem.writeInt(u16, response[question.question_end - 2 ..][0..2], 255, .big);

    try std.testing.expectError(error.QuestionMismatch, prepareUpstreamResponse(&request_map, upstream_addr, &response));
    try std.testing.expectEqual(@as(u32, 1), request_map.count());
}

test "upstream response validation rejects matching ID with wrong sender" {
    var request_map = ActiveRequestMap.init(std.testing.allocator);
    defer request_map.deinit();

    var original_request = try bytesFromHex("cfc9010000010000000000000a6475636b6475636b676f03636f6d0000010001");
    var response = try bytesFromHex("1234818000010000000000000a6475636b6475636b676f03636f6d0000010001");
    const client_addr = try std.net.Address.parseIp4("127.0.0.1", 1234);
    const upstream_addr = try std.net.Address.parseIp4("9.9.9.9", 53);
    const wrong_upstream_addr = try std.net.Address.parseIp4("1.1.1.1", 53);
    try request_map.put(0x1234, try makeActiveRequest(0xcfc9, client_addr, upstream_addr, &original_request, 1_000));

    try std.testing.expectError(error.UnexpectedUpstreamSender, prepareUpstreamResponse(&request_map, wrong_upstream_addr, &response));
    try std.testing.expectEqual(@as(u32, 1), request_map.count());
}

test "header-only upstream error response restores original client ID and keeps active request pending" {
    var request_map = ActiveRequestMap.init(std.testing.allocator);
    defer request_map.deinit();

    var original_request = try bytesFromHex("cfc9010000010000000000000a6475636b6475636b676f03636f6d0000010001");
    var response = makeHeaderOnlyResponse(0x1234, dns_flag_qr | 0x0100 | 0x0080 | dns_rcode_servfail);
    const client_addr = try std.net.Address.parseIp4("127.0.0.1", 1234);
    const upstream_addr = try std.net.Address.parseIp4("9.9.9.9", 53);
    try request_map.put(0x1234, try makeActiveRequest(0xcfc9, client_addr, upstream_addr, &original_request, 1_000));

    const resolved_client_addr = (try prepareUpstreamResponse(&request_map, upstream_addr, &response)).client_addr;

    try std.testing.expect(client_addr.eql(resolved_client_addr));
    try std.testing.expectEqual(@as(u16, 0xcfc9), std.mem.readInt(u16, response[0..2], .big));
    try std.testing.expectEqual(@as(u32, 1), request_map.count());
}

test "questionless upstream error response allows opt additional record" {
    var request_map = ActiveRequestMap.init(std.testing.allocator);
    defer request_map.deinit();

    var original_request = try bytesFromHex("cfc9010000010000000000000a6475636b6475636b676f03636f6d0000010001");
    var response = try bytesFromHex("12348185000000000000000100002904d0000000000000");
    const client_addr = try std.net.Address.parseIp4("127.0.0.1", 1234);
    const upstream_addr = try std.net.Address.parseIp4("9.9.9.9", 53);
    try request_map.put(0x1234, try makeActiveRequest(0xcfc9, client_addr, upstream_addr, &original_request, 1_000));

    const resolved_client_addr = (try prepareUpstreamResponse(&request_map, upstream_addr, &response)).client_addr;

    try std.testing.expect(client_addr.eql(resolved_client_addr));
    try std.testing.expectEqual(@as(u16, 0xcfc9), std.mem.readInt(u16, response[0..2], .big));
    try std.testing.expectEqual(@as(u32, 1), request_map.count());
}

test "upstream response with a question but no response bit is rejected" {
    var request_map = ActiveRequestMap.init(std.testing.allocator);
    defer request_map.deinit();

    var original_request = try bytesFromHex("cfc9010000010000000000000a6475636b6475636b676f03636f6d0000010001");
    // Identical to the pending question, but QR=0: an echoed query, not a response.
    var response = try bytesFromHex("1234010000010000000000000a6475636b6475636b676f03636f6d0000010001");
    const client_addr = try std.net.Address.parseIp4("127.0.0.1", 1234);
    const upstream_addr = try std.net.Address.parseIp4("9.9.9.9", 53);
    try request_map.put(0x1234, try makeActiveRequest(0xcfc9, client_addr, upstream_addr, &original_request, 1_000));

    try std.testing.expectError(error.NotUpstreamResponse, prepareUpstreamResponse(&request_map, upstream_addr, &response));
    try std.testing.expectEqual(@as(u32, 1), request_map.count());
}

test "upstream response with multiple questions is rejected" {
    var request_map = ActiveRequestMap.init(std.testing.allocator);
    defer request_map.deinit();

    var original_request = try bytesFromHex("cfc9010000010000000000000a6475636b6475636b676f03636f6d0000010001");
    // QDCOUNT=2 with a first question matching the pending request.
    var response = try bytesFromHex("1234818000020000000000000a6475636b6475636b676f03636f6d0000010001");
    const client_addr = try std.net.Address.parseIp4("127.0.0.1", 1234);
    const upstream_addr = try std.net.Address.parseIp4("9.9.9.9", 53);
    try request_map.put(0x1234, try makeActiveRequest(0xcfc9, client_addr, upstream_addr, &original_request, 1_000));

    try std.testing.expectError(error.UnexpectedQuestionCount, prepareUpstreamResponse(&request_map, upstream_addr, &response));
    try std.testing.expectEqual(@as(u32, 1), request_map.count());
}

test "header-only upstream error without response bit is rejected" {
    var request_map = ActiveRequestMap.init(std.testing.allocator);
    defer request_map.deinit();

    var original_request = try bytesFromHex("cfc9010000010000000000000a6475636b6475636b676f03636f6d0000010001");
    var response = makeHeaderOnlyResponse(0x1234, 0x0100 | dns_rcode_servfail);
    const client_addr = try std.net.Address.parseIp4("127.0.0.1", 1234);
    const upstream_addr = try std.net.Address.parseIp4("9.9.9.9", 53);
    try request_map.put(0x1234, try makeActiveRequest(0xcfc9, client_addr, upstream_addr, &original_request, 1_000));

    try std.testing.expectError(error.NotUpstreamResponse, prepareUpstreamResponse(&request_map, upstream_addr, &response));
    try std.testing.expectEqual(@as(u32, 1), request_map.count());
}

test "matching upstream response restores original client ID and keeps active request pending" {
    var request_map = ActiveRequestMap.init(std.testing.allocator);
    defer request_map.deinit();

    var original_request = try bytesFromHex("cfc9010000010000000000000a6475636b6475636b676f03636f6d0000010001");
    var response = try bytesFromHex("1234818000010000000000000a6475636b6475636b676f03636f6d0000010001");
    const client_addr = try std.net.Address.parseIp4("127.0.0.1", 1234);
    const upstream_addr = try std.net.Address.parseIp4("9.9.9.9", 53);
    try request_map.put(0x1234, try makeActiveRequest(0xcfc9, client_addr, upstream_addr, &original_request, 1_000));

    const resolved_client_addr = (try prepareUpstreamResponse(&request_map, upstream_addr, &response)).client_addr;

    try std.testing.expect(client_addr.eql(resolved_client_addr));
    try std.testing.expectEqual(@as(u16, 0xcfc9), std.mem.readInt(u16, response[0..2], .big));
    try std.testing.expectEqual(@as(u32, 1), request_map.count());
}

test "matching upstream response accepts case-only qname differences" {
    var request_map = ActiveRequestMap.init(std.testing.allocator);
    defer request_map.deinit();

    var original_request = try bytesFromHex("cfc9010000010000000000000a4475636b4475636b476f03434f4d0000010001");
    var response = try bytesFromHex("1234818000010000000000000a6475636b6475636b676f03636f6d0000010001");
    const original_response = response;
    const client_addr = try std.net.Address.parseIp4("127.0.0.1", 1234);
    const upstream_addr = try std.net.Address.parseIp4("9.9.9.9", 53);
    try request_map.put(0x1234, try makeActiveRequest(0xcfc9, client_addr, upstream_addr, &original_request, 1_000));

    const resolved_client_addr = (try prepareUpstreamResponse(&request_map, upstream_addr, &response)).client_addr;

    try std.testing.expect(client_addr.eql(resolved_client_addr));
    try std.testing.expectEqual(@as(u16, 0xcfc9), std.mem.readInt(u16, response[0..2], .big));
    try std.testing.expectEqualSlices(u8, original_response[2..], response[2..]);
    try std.testing.expectEqual(@as(u32, 1), request_map.count());
}

test "completed upstream request removes active request after downstream send is queued" {
    var request_map = ActiveRequestMap.init(std.testing.allocator);
    defer request_map.deinit();

    var original_request = try bytesFromHex("cfc9010000010000000000000a6475636b6475636b676f03636f6d0000010001");
    var response = try bytesFromHex("1234818000010000000000000a6475636b6475636b676f03636f6d0000010001");
    const client_addr = try std.net.Address.parseIp4("127.0.0.1", 1234);
    const upstream_addr = try std.net.Address.parseIp4("9.9.9.9", 53);
    try request_map.put(0x1234, try makeActiveRequest(0xcfc9, client_addr, upstream_addr, &original_request, 1_000));

    _ = try prepareUpstreamResponse(&request_map, upstream_addr, &response);
    try std.testing.expectEqual(@as(u32, 1), request_map.count());

    completeUpstreamRequest(&request_map, 0x1234);
    try std.testing.expectEqual(@as(u32, 0), request_map.count());
}

test "cleanup removes expired active requests and keeps unexpired requests" {
    var request_map = ActiveRequestMap.init(std.testing.allocator);
    defer request_map.deinit();
    var retired_request_ids = RetiredRequestIdMap.init(std.testing.allocator);
    defer retired_request_ids.deinit();
    // Production init reserves capacity so quarantine inserts cannot fail.
    try retired_request_ids.ensureTotalCapacity(max_in_flight_requests);

    var request = try bytesFromHex("cfc9010000010000000000000a6475636b6475636b676f03636f6d0000010001");
    const client_addr = try std.net.Address.parseIp4("127.0.0.1", 1234);
    const upstream_addr = try std.net.Address.parseIp4("9.9.9.9", 53);
    try request_map.put(1, try makeActiveRequest(100, client_addr, upstream_addr, &request, 100));
    try request_map.put(2, try makeActiveRequest(101, client_addr, upstream_addr, &request, 300));

    try std.testing.expectEqual(@as(usize, 1), cleanupExpiredRequests(&request_map, &retired_request_ids, 200));
    try std.testing.expect(!request_map.contains(1));
    try std.testing.expect(request_map.contains(2));
    try std.testing.expectEqual(@as(u64, 200 + expired_request_id_quarantine_ns), retired_request_ids.get(1).?);
    try std.testing.expect(!retired_request_ids.contains(2));
}

test "cleanup skips empty request maps" {
    var request_map = ActiveRequestMap.init(std.testing.allocator);
    defer request_map.deinit();
    var retired_request_ids = RetiredRequestIdMap.init(std.testing.allocator);
    defer retired_request_ids.deinit();

    try std.testing.expectEqual(@as(usize, 0), cleanupExpiredRequests(&request_map, &retired_request_ids, 200));
    try std.testing.expectEqual(@as(usize, 0), cleanupRetiredRequestIds(&retired_request_ids, 200));
}

test "cleanup retired request IDs removes only expired quarantine entries" {
    var retired_request_ids = RetiredRequestIdMap.init(std.testing.allocator);
    defer retired_request_ids.deinit();
    try retired_request_ids.put(1, 100);
    try retired_request_ids.put(2, 300);

    try std.testing.expectEqual(@as(usize, 1), cleanupRetiredRequestIds(&retired_request_ids, 200));
    try std.testing.expect(!retired_request_ids.contains(1));
    try std.testing.expect(retired_request_ids.contains(2));
}

test "cleanup retired request IDs handles more entries than the in-flight cap" {
    var retired_request_ids = RetiredRequestIdMap.init(std.testing.allocator);
    defer retired_request_ids.deinit();

    const retired_count = max_in_flight_requests + 16;
    for (0..retired_count) |id| {
        try retired_request_ids.put(@intCast(id), 100);
    }

    // Removal is batched to max_in_flight_requests per call; the remainder
    // drains on the next tick.
    try std.testing.expectEqual(@as(usize, max_in_flight_requests), cleanupRetiredRequestIds(&retired_request_ids, 200));
    try std.testing.expectEqual(@as(usize, 16), cleanupRetiredRequestIds(&retired_request_ids, 200));
    try std.testing.expectEqual(@as(u32, 0), retired_request_ids.count());
}

test "send pool acquire copies data and stores destination" {
    var pool = SendPool{};
    const addr = try std.net.Address.parseIp4("127.0.0.1", 5300);
    const data = "dns packet";

    const slot = try pool.acquire(.local, addr, data);

    try std.testing.expect(slot.in_use);
    try std.testing.expectEqual(data.len, slot.len);
    try std.testing.expect(addr.eql(slot.addr));
    try std.testing.expectEqual(SendDirection.local, slot.direction);
    try std.testing.expectEqualSlices(u8, data, slot.buffer[0..slot.len]);
}

test "send pool release makes slot reusable" {
    var pool = SendPool{};
    const addr = try std.net.Address.parseIp4("127.0.0.1", 5300);

    const first = try pool.acquire(.local, addr, "first");
    first.release();
    pool.next_slot = 0;
    const second = try pool.acquire(.upstream, addr, "second");

    try std.testing.expect(first == second);
    try std.testing.expect(second.in_use);
    try std.testing.expectEqual(SendDirection.upstream, second.direction);
    try std.testing.expectEqualSlices(u8, "second", second.buffer[0..second.len]);
}

test "send pool exhaustion returns NoSendSlots" {
    var pool = SendPool{};
    const addr = try std.net.Address.parseIp4("127.0.0.1", 5300);

    for (0..max_send_slots) |_| {
        _ = try pool.acquire(.local, addr, "x");
    }

    try std.testing.expectError(error.NoSendSlots, pool.acquire(.local, addr, "x"));
}

test "send pool rotating acquisition skips occupied slots" {
    var pool = SendPool{};
    const addr = try std.net.Address.parseIp4("127.0.0.1", 5300);

    const occupied = try pool.acquire(.local, addr, "occupied");
    pool.next_slot = 0;
    const next = try pool.acquire(.local, addr, "next");

    try std.testing.expect(occupied == &pool.slots[0]);
    try std.testing.expect(next == &pool.slots[1]);
    try std.testing.expect(occupied.in_use);
    try std.testing.expect(next.in_use);
    try std.testing.expectEqual(@as(usize, 2), pool.next_slot);
}

test "blocked nullip response returns AAAA :: for AAAA queries" {
    var request = try bytesFromHex("000101000001000000000000076578616d706c6503636f6d00001c0001");

    var domain_buffer: [256]u8 = undefined;
    const question = try util.parseDnsQuestion(&domain_buffer, &request);

    var response_buffer: [512]u8 = undefined;
    const response = try buildBlockedResponse(&response_buffer, &request, question, .nullip);

    try std.testing.expectEqual(@as(usize, question.question_end + 28), response.len);
    try std.testing.expectEqual(@as(u8, 0), response[6]);
    try std.testing.expectEqual(@as(u8, 1), response[7]);

    const answer_prefix = [_]u8{
        0xC0, 0x0C, // name pointer
        0x00, 0x1C, // AAAA
        0x00, 0x01, // IN
        0x00, 0x00, 0x00, 0x3C, // TTL
        0x00, 0x10, // RDLENGTH
    };
    try std.testing.expectEqualSlices(u8, &answer_prefix, response[question.question_end .. question.question_end + answer_prefix.len]);
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 16), response[question.question_end + answer_prefix.len ..]);
}

test "blocked nullip response returns NODATA for other query types" {
    var request = try bytesFromHex("000101000001000000000000076578616d706c6503636f6d0000410001");

    var domain_buffer: [256]u8 = undefined;
    const question = try util.parseDnsQuestion(&domain_buffer, &request);

    var response_buffer: [512]u8 = undefined;
    const response = try buildBlockedResponse(&response_buffer, &request, question, .nullip);

    try std.testing.expectEqual(@as(usize, question.question_end), response.len);
    try std.testing.expect(response[2] & 0x80 != 0);
    try std.testing.expectEqual(@as(u8, 0), response[3] & 0x0F);
    try std.testing.expectEqual(@as(u8, 0), response[6]);
    try std.testing.expectEqual(@as(u8, 0), response[7]);
}

test "blocked nxdomain response returns NXDOMAIN without answers" {
    var request = try bytesFromHex("cfc9010000010000000000000a6475636b6475636b676f03636f6d0000010001");

    var domain_buffer: [256]u8 = undefined;
    const question = try util.parseDnsQuestion(&domain_buffer, &request);

    var response_buffer: [512]u8 = undefined;
    const response = try buildBlockedResponse(&response_buffer, &request, question, .nxdomain);

    try std.testing.expectEqual(@as(usize, question.question_end), response.len);
    try std.testing.expect(response[2] & 0x80 != 0);
    try std.testing.expectEqual(@as(u8, 3), response[3] & 0x0F);
    try std.testing.expectEqual(@as(u8, 0), response[6]);
    try std.testing.expectEqual(@as(u8, 0), response[7]);
}

test {
    std.testing.refAllDecls(@This());
}
