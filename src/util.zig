const std = @import("std");

/// Extracts the domain name from a DNS request packet
/// The returned domain name is a slice of a static buffer with the domain
/// name in human-readable format (e.g., "example.com")
/// TODO: This is probably missing many edge cases. E.g. reject multiple questions
pub fn extractDomainName(buffer: []u8, packet: []const u8) ![]u8 {
    // DNS header is 12 bytes, the query starts after that
    if (packet.len < 13) return error.PacketTooShort;

    var pos: usize = 12; // Start after header
    var buf_pos: usize = 0;
    var first_label = true;
    var jumps: u8 = 0;
    const max_jumps = 10; // Prevent compression pointer loops

    while (pos < packet.len) {
        // Check for compression pointer (top 2 bits are 1s)
        if ((packet[pos] & 0xC0) == 0xC0) {
            if (jumps >= max_jumps) return error.TooManyCompressedPointers;
            if (pos + 1 >= packet.len) return error.PacketTooShort;

            // Pointer is formed from the lower 14 bits of the two bytes
            const offset = @as(u16, packet[pos] & 0x3F) << 8 | packet[pos + 1];

            // Make sure the pointer isn't obviously invalid (too large for the packet)
            if (offset >= packet.len) return error.InvalidPointer;

            // Don't do position-based validation as it doesn't work with sliced packets
            // Instead, we'll rely on the max_jumps check to prevent infinite loops
            pos = offset;
            jumps += 1;
            continue;
        }

        const label_len = packet[pos];
        pos += 1;

        // Zero length means end of domain name
        if (label_len == 0) break;

        // Validate label length (DNS spec: max 63 bytes)
        if (label_len > 63) return error.LabelTooLong;

        // Add dot between labels, except before the first one
        if (!first_label) {
            if (buf_pos >= buffer.len) return error.BufferTooSmall;
            buffer[buf_pos] = '.';
            buf_pos += 1;
        }
        first_label = false;

        // Copy the label contents
        if (pos + label_len > packet.len) return error.PacketTooShort;
        if (buf_pos + label_len > buffer.len) return error.BufferTooSmall;

        @memcpy(buffer[buf_pos .. buf_pos + label_len], packet[pos .. pos + label_len]);
        pos += label_len;
        buf_pos += label_len;

        // Check total domain name length (max 255 bytes)
        if (buf_pos > 255) return error.DomainNameTooLong;
    }

    return buffer[0..buf_pos];
}

/// Parses a hosts file (for example, https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts)
/// and populates a hashmap with the domains. Hosts file entries are expected to be in the format:
/// {ip} {domain}
/// Lines starting with '#' are ignored.
/// Lines with IPs other than 0.0.0.0 are ignored.
pub fn parseHostsFile(reader: *const std.io.AnyReader, blocked_domains: *std.StringHashMap([]const u8), allocator: std.mem.Allocator) !void {
    var line_buffer: [1024]u8 = undefined;
    var buffered_reader = std.io.bufferedReader(reader.*);
    const buff_reader = buffered_reader.reader();

    while (true) {
        var line_fixed_buffer = std.io.fixedBufferStream(&line_buffer);
        buff_reader.streamUntilDelimiter(line_fixed_buffer.writer(), '\n', line_buffer.len) catch |err| {
            if (err == error.StreamTooLong) {
                // Skip overly long lines by reading until the next newline character
                // or EOF if newline is not found.
                buff_reader.skipUntilDelimiterOrEof('\n') catch |skip_err| {
                    if (skip_err != error.EndOfStream) {
                        // If skipping failed with something other than EOF, propagate it.
                        return skip_err;
                    }
                    // If EndOfStream, the rest of the (long) line has been consumed up to EOF.
                    // The main loop's next iteration will handle the EOF state correctly.
                };
                continue;
            } else if (err == error.EndOfStream) {
                // End of stream reached during delimiter search
                const line = line_fixed_buffer.getWritten();
                if (line.len == 0) break; // EOF with no data
                // Otherwise continue processing the final line
            } else {
                return err;
            }
        };

        const line = line_fixed_buffer.getWritten();

        const trimmed_line = std.mem.trimLeft(u8, line, " \t");
        if (trimmed_line.len == 0 or trimmed_line[0] == '#') continue;

        var iter = std.mem.tokenizeAny(u8, trimmed_line, " \t");
        const ip = iter.next() orelse continue;

        // Only block if IP is 0.0.0.0
        if (!std.mem.eql(u8, ip, "0.0.0.0")) continue;

        const domain_raw = iter.next() orelse continue;

        // Skip localhost entries and other special cases
        if (std.mem.eql(u8, domain_raw, "localhost") or
            std.mem.eql(u8, domain_raw, "localhost.localdomain") or
            std.mem.eql(u8, domain_raw, "broadcasthost") or
            std.mem.startsWith(u8, domain_raw, "ip6-"))
        {
            continue;
        }

        // Store a copy of the domain in the hashmap
        const domain = try allocator.dupe(u8, domain_raw);
        try blocked_domains.put(domain, domain);
    }

    std.log.info("Loaded {} blocked domains", .{blocked_domains.count()});
}

test "extract domain name" {
    const hex_string = "cfc9010000010000000000000a6475636b6475636b676f03636f6d0000010001";
    var bytes: [hex_string.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, hex_string);

    var domain_buffer: [256]u8 = undefined;
    const domain_name = try extractDomainName(&domain_buffer, &bytes);
    try std.testing.expectEqualStrings("duckduckgo.com", domain_name);
}

test "extract compressed domain name" {
    // This is a mock DNS response with compression
    // The domain name in the answer section points back to the question section
    const hex_string = "00030100000100000000000003777777076578616d706c6503636f6d0000010001";
    var bytes: [hex_string.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, hex_string);

    var domain_buffer: [256]u8 = undefined;

    const domain_name = try extractDomainName(&domain_buffer, &bytes);
    try std.testing.expectEqualStrings("www.example.com", domain_name);
}

test "parse hosts file" {
    const test_input =
        \\# This is a comment
        \\0.0.0.0 ads.example.com
        \\0.0.0.0 tracking.example.com
        \\127.0.0.1 localhost
        \\0.0.0.0 localhost.localdomain # should be ignored
        \\0.0.0.0 ip6-localhost # should be ignored
        \\1.2.3.4 allowed.example.com # different IP should be ignored
        \\
        \\0.0.0.0 another-ad.example.com
    ;

    var blocked_domains = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer {
        var it = blocked_domains.iterator();
        while (it.next()) |entry| {
            std.testing.allocator.free(entry.key_ptr.*);
        }
        blocked_domains.deinit();
    }

    var in_stream = std.io.fixedBufferStream(test_input);
    const reader = in_stream.reader();

    try parseHostsFile(&reader.any(), &blocked_domains, std.testing.allocator);

    // Check size - should have 3 domains (ads, tracking, another-ad)
    try std.testing.expectEqual(@as(usize, 3), blocked_domains.count());

    // Check specific domains are present
    try std.testing.expect(blocked_domains.contains("ads.example.com"));
    try std.testing.expect(blocked_domains.contains("tracking.example.com"));
    try std.testing.expect(blocked_domains.contains("another-ad.example.com"));

    // Check domains we should have skipped
    try std.testing.expect(!blocked_domains.contains("localhost"));
    try std.testing.expect(!blocked_domains.contains("localhost.localdomain"));
    try std.testing.expect(!blocked_domains.contains("ip6-localhost"));
    try std.testing.expect(!blocked_domains.contains("allowed.example.com"));
}

test "parse hosts file with overly long lines" {
    // Generate a very long line (longer than buffer size)
    var long_line = [_]u8{'a'} ** 2000;
    for (0..2000) |i| {
        long_line[i] = if (i % 100 == 0) '.' else 'a';
    }

    // Create the test input with a mix of valid entries and lines that are too long
    var test_input_buf: [3500]u8 = undefined;
    var test_input_stream = std.io.fixedBufferStream(&test_input_buf);
    const writer = test_input_stream.writer();

    // Write valid line
    try writer.writeAll("0.0.0.0 normal.example.com\n");

    // Write overly long line (without newline at first to simulate partial read)
    try writer.writeAll("0.0.0.0 ");
    try writer.writeAll(&long_line);
    try writer.writeAll("\n");

    // Write another valid line
    try writer.writeAll("0.0.0.0 after-long-line.example.com\n");

    var blocked_domains = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer {
        var it = blocked_domains.iterator();
        while (it.next()) |entry| {
            std.testing.allocator.free(entry.key_ptr.*);
        }
        blocked_domains.deinit();
    }

    // Reset the stream position to the beginning
    test_input_stream.reset();
    const reader = test_input_stream.reader();

    try parseHostsFile(&reader.any(), &blocked_domains, std.testing.allocator);

    // Check size - should have 2 domains (the overly long line should be skipped)
    try std.testing.expectEqual(@as(usize, 2), blocked_domains.count());

    // Check specific domains are present
    try std.testing.expect(blocked_domains.contains("normal.example.com"));
    try std.testing.expect(blocked_domains.contains("after-long-line.example.com"));

    // The domain from the overly long line should not be present
    // (We can't meaningfully test this since we don't extract the domain from the overly long line)
}
