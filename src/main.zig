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

const RequestSender = struct {
    addr: std.net.Address,
    id: u16,
};

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

fn buildBlockedResponse(buffer: []u8, request: []const u8, question: util.DnsQuestion, block_mode: BlockMode) ![]u8 {
    if (question.question_end > request.len or question.question_end > buffer.len) return error.PacketTooShort;

    @memcpy(buffer[0..question.question_end], request[0..question.question_end]);

    buffer[2] = buffer[2] | 0x80; // QR
    buffer[3] = buffer[3] & 0xF0; // RCODE
    std.mem.writeInt(u16, buffer[6..][0..2], 0, .big); // ANCOUNT
    std.mem.writeInt(u16, buffer[8..][0..2], 0, .big); // NSCOUNT
    std.mem.writeInt(u16, buffer[10..][0..2], 0, .big); // ARCOUNT

    switch (block_mode) {
        .nxdomain => {
            buffer[3] = buffer[3] | 0x03; // NXDOMAIN
            return buffer[0..question.question_end];
        },
        .nullip => {
            const pos = question.question_end;
            const rdata_len: usize = switch (question.qtype) {
                1 => 4, // A
                28 => 16, // AAAA
                else => 0,
            };

            if (question.qclass != 1 or rdata_len == 0) {
                return buffer[0..pos];
            }

            std.mem.writeInt(u16, buffer[6..][0..2], 1, .big); // ANCOUNT

            var writer = PacketWriter{ .buffer = buffer, .pos = pos };
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

const ForwardingServer = struct {
    upstream_server: UpstreamServer,
    local_server: LocalServer,
    request_map: std.AutoHashMap(u16, RequestSender),
    blocked_domains: std.StringHashMap([]const u8),
    block_mode: BlockMode,

    pub fn init(local_addr: std.net.Address, upstream_addr: std.net.Address, alloc: std.mem.Allocator, block_mode_param: BlockMode, blocked_domains_param: std.StringHashMap([]const u8)) !ForwardingServer {
        return .{
            .upstream_server = try UpstreamServer.init(upstream_addr),
            .local_server = try LocalServer.init(local_addr),
            .request_map = std.AutoHashMap(u16, RequestSender).init(alloc),
            .blocked_domains = blocked_domains_param,
            .block_mode = block_mode_param,
        };
    }

    pub fn deinit(self: *ForwardingServer) void {
        var it = self.blocked_domains.iterator();
        while (it.next()) |entry| {
            self.blocked_domains.allocator.free(entry.key_ptr.*);
        }
        self.blocked_domains.deinit();
        self.request_map.deinit();
    }

    pub fn start(self: *ForwardingServer, loop: *xev.Loop) !void {
        try self.upstream_server.start(loop, ForwardingServer, self, ForwardingServer.upstreamReadCallback);
        try self.local_server.start(loop, ForwardingServer, self, ForwardingServer.localReadCallback);
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

        // parse the request ID from the response
        const request_id = std.mem.readInt(u16, data[0..2], .big);

        std.log.debug("recv - upstm - id: {d} - {d} bytes ({})\n", .{ request_id, n, sender });

        const result = self.?.request_map.fetchRemove(request_id) orelse {
            std.log.warn("Failed to fetch request ID {}\n", .{request_id});
            return .rearm;
        };

        try self.?.local_server.sendTo(loop, result.value.addr, data);

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

        // parse the request ID from the response
        const request_id = std.mem.readInt(u16, data[0..2], .big);

        std.log.debug("recv - local - id: {d} - {d} bytes from {}\n", .{ request_id, n, sender });

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

            std.log.info("DNS query: qname={s} qtype={s} qclass={s}", .{ question.qname, qtype_display, qclass_display });
        }

        // Check if domain is blocked
        if (self.?.blocked_domains.contains(question.qname)) {
            std.log.info("Blocking domain: {s}", .{question.qname});

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

        // TODO: Check for conflicting request IDs
        self.?.request_map.put(request_id, RequestSender{ .addr = sender, .id = request_id }) catch |err| {
            std.log.warn("Failed to put request ID {}: {}\n", .{ request_id, err });
            return .rearm;
        };

        try self.?.upstream_server.send(loop, data);

        return .rearm;
    }
};

const UpstreamServer = struct {
    udp: xev.UDP,
    addr: std.net.Address,
    udp_send_state: xev.UDP.State = undefined,
    udp_recv_state: xev.UDP.State = undefined,
    c_recv: xev.Completion = undefined,
    c_send: xev.Completion = undefined,
    recv_buf: [512]u8 = undefined,

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

        self.udp.write(loop, &self.c_send, &self.udp_send_state, self.addr, .{ .slice = data }, UpstreamServer, self, UpstreamServer.writeCallback);
    }

    fn writeCallback(
        self: ?*UpstreamServer,
        _: *xev.Loop,
        _: *xev.Completion,
        _: *xev.UDP.State,
        _: xev.UDP,
        _: xev.WriteBuffer,
        r: xev.WriteError!usize,
    ) xev.CallbackAction {
        const n = r catch |err| {
            std.log.warn("err={}", .{err});
            return .disarm;
        };

        std.log.debug("send - upstm - {d} bytes ({})\n", .{ n, self.?.addr });

        return .disarm;
    }
};

const LocalServer = struct {
    udp: xev.UDP,
    addr: std.net.Address,
    udp_recv_state: xev.UDP.State = undefined,
    udp_send_state: xev.UDP.State = undefined,
    c_recv: xev.Completion = undefined,
    c_send: xev.Completion = undefined,
    recv_buf: [512]u8 = undefined,

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
        self.udp.write(loop, &self.c_send, &self.udp_send_state, addr, .{ .slice = data }, LocalServer, self, LocalServer.writeCallback);
    }

    fn writeCallback(
        self: ?*LocalServer,
        _: *xev.Loop,
        _: *xev.Completion,
        _: *xev.UDP.State,
        _: xev.UDP,
        _: xev.WriteBuffer,
        r: xev.WriteError!usize,
    ) xev.CallbackAction {
        const n = r catch |err| {
            std.log.warn("err={}", .{err});
            return .disarm;
        };

        std.log.debug("send - local - {d} bytes ({})\n", .{ n, self.?.addr });

        return .disarm;
    }
};

test "blocked nullip response returns A 0.0.0.0 for A queries" {
    const hex_string = "cfc9010000010000000000000a6475636b6475636b676f03636f6d0000010001";
    var request: [hex_string.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&request, hex_string);

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

test "blocked nullip response returns AAAA :: for AAAA queries" {
    const hex_string = "000101000001000000000000076578616d706c6503636f6d00001c0001";
    var request: [hex_string.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&request, hex_string);

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
    const hex_string = "000101000001000000000000076578616d706c6503636f6d0000410001";
    var request: [hex_string.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&request, hex_string);

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
    const hex_string = "cfc9010000010000000000000a6475636b6475636b676f03636f6d0000010001";
    var request: [hex_string.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&request, hex_string);

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
