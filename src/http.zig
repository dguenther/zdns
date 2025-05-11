const std = @import("std");
const util = @import("util.zig");

pub fn requestHostsFile(url: []const u8, blocked_domains: *std.StringHashMap([]const u8), alloc: std.mem.Allocator) !void {
    var buf: [4096]u8 = undefined;

    // Create an HTTP client.
    var client = std.http.Client{ .allocator = alloc };
    // Release all associated resources with the client.
    defer client.deinit();

    // Parse the URI.
    const uri = std.Uri.parse(url) catch unreachable;

    // Create the headers that will be sent to the server.
    const headers = &[_]std.http.Header{
        .{ .name = "accept", .value = "*/*" },
    };

    // Make the connection to the server.
    var request = try client.open(.GET, uri, .{
        .server_header_buffer = &buf,
        .extra_headers = headers,
    });
    defer request.deinit();
    try request.send();
    try request.finish();

    // Wait for the server to send use a response.
    try request.wait();

    try util.parseHostsFile(&request.reader().any(), blocked_domains, alloc);
}
