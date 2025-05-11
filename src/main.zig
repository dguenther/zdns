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
        const request_id: u16 = @as(u16, data[0]) << 8 | data[1];

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
        const request_id: u16 = @as(u16, data[0]) << 8 | data[1];

        std.log.debug("recv - local - id: {d} - {d} bytes from {}\n", .{ request_id, n, sender });

        var domain_buffer: [256]u8 = undefined;
        const domain_name = util.extractDomainName(&domain_buffer, data) catch |err| {
            std.log.warn("Failed to extract domain name: {}\n", .{err});
            return .rearm;
        };

        std.log.info("DNS query for domain: {s}", .{domain_name});

        // Check if domain is blocked
        if (self.?.blocked_domains.contains(domain_name)) {
            std.log.info("Blocking domain: {s}", .{domain_name});

            // Create a response packet based on the request
            var response_buffer: [512]u8 = undefined;
            @memcpy(response_buffer[0..n], data);

            // Set QR bit to indicate this is a response
            response_buffer[2] = response_buffer[2] | 0x80; // Set QR bit

            switch (self.?.block_mode) {
                .nxdomain => {
                    // Set response flags for NXDOMAIN (domain doesn't exist)
                    response_buffer[3] = response_buffer[3] & 0xF0; // Clear RCODE
                    response_buffer[3] = response_buffer[3] | 0x03; // Set RCODE=3 (NXDOMAIN)
                },

                .nullip => {
                    // Send 0.0.0.0 as the response
                    // Standard response
                    response_buffer[3] = response_buffer[3] & 0xF0; // Clear RCODE

                    // Set answer count to 1
                    response_buffer[6] = 0;
                    response_buffer[7] = 1;

                    // Keep original query data
                    var pos: usize = 12;

                    // Skip the question section (domain name + QTYPE + QCLASS)
                    while (pos < n) {
                        if (pos + 1 >= n) break; // Ensure we don't go out of bounds

                        // Check for compression pointer (top 2 bits are 1s)
                        if ((response_buffer[pos] & 0xC0) == 0xC0) {
                            pos += 2; // Skip the 2-byte compression pointer
                            break;
                        }

                        // Skip over the label
                        const label_len = response_buffer[pos];
                        if (label_len == 0) {
                            pos += 1; // Skip the null byte
                            break;
                        }

                        pos += label_len + 1; // Skip the length byte and the label
                    }

                    // Skip QTYPE and QCLASS (4 bytes)
                    pos += 4;

                    // Add answer section
                    // Answer name is a pointer to the question
                    response_buffer[pos] = 0xC0;
                    response_buffer[pos + 1] = 0x0C; // Pointer to offset 12 (start of question)
                    pos += 2;

                    // Type: A record (0x0001)
                    response_buffer[pos] = 0x00;
                    response_buffer[pos + 1] = 0x01;
                    pos += 2;

                    // Class: IN (0x0001)
                    response_buffer[pos] = 0x00;
                    response_buffer[pos + 1] = 0x01;
                    pos += 2;

                    // TTL: 60 seconds (0x0000003C)
                    response_buffer[pos] = 0x00;
                    response_buffer[pos + 1] = 0x00;
                    response_buffer[pos + 2] = 0x00;
                    response_buffer[pos + 3] = 0x3C;
                    pos += 4;

                    // Data length: 4 bytes for IPv4
                    response_buffer[pos] = 0x00;
                    response_buffer[pos + 1] = 0x04;
                    pos += 2;

                    // IP: 0.0.0.0
                    response_buffer[pos] = 0x00;
                    response_buffer[pos + 1] = 0x00;
                    response_buffer[pos + 2] = 0x00;
                    response_buffer[pos + 3] = 0x00;
                    pos += 4;

                    // Update packet length - cast to ensure proper type
                    const response_size: usize = pos;

                    // Send the response back to the client
                    self.?.local_server.sendTo(loop, sender, response_buffer[0..response_size]) catch |err| {
                        std.log.warn("Failed to send blocked response: {}\n", .{err});
                    };

                    return .rearm;
                },
            }

            // Send the response back to the client for NXDOMAIN case
            self.?.local_server.sendTo(loop, sender, response_buffer[0..n]) catch |err| {
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

test {
    std.testing.refAllDecls(@This());
}
