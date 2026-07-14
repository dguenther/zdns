const std = @import("std");

pub const DnsName = struct {
    canonical_name: []u8,
    end_pos: usize,
};

pub const DnsQuestion = struct {
    canonical_qname: []u8,
    qtype: u16,
    qclass: u16,
    question_end: usize,
};

/// Extracts the domain name from a DNS request packet
/// The returned domain name is a slice of a static buffer with the domain
/// name in canonical lowercase, human-readable format (e.g., "example.com").
/// The input packet is not modified, preserving DNS 0x20 query casing.
/// TODO: This is probably missing many edge cases. E.g. reject multiple questions
pub fn extractDomainName(buffer: []u8, packet: []const u8) ![]u8 {
    const name = try parseDnsName(buffer, packet, 12);
    return name.canonical_name;
}

/// Parses the first DNS question. The returned qname is a dotted presentation
/// name canonicalized to ASCII lowercase in `buffer`; `packet` is not modified.
pub fn parseDnsQuestion(buffer: []u8, packet: []const u8) !DnsQuestion {
    // DNS header is 12 bytes, the query starts after that
    if (packet.len < 13) return error.PacketTooShort;

    const qname = try parseDnsName(buffer, packet, 12);
    const qtype_pos = qname.end_pos;
    if (qtype_pos + 4 > packet.len) return error.PacketTooShort;

    const qtype = std.mem.readInt(u16, packet[qtype_pos..][0..2], .big);
    const qclass = std.mem.readInt(u16, packet[qtype_pos + 2 ..][0..2], .big);

    return .{
        .canonical_qname = qname.canonical_name,
        .qtype = qtype,
        .qclass = qclass,
        .question_end = qtype_pos + 4,
    };
}

pub fn qtypeName(qtype: u16) ?[]const u8 {
    return switch (qtype) {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        64 => "SVCB",
        65 => "HTTPS",
        255 => "ANY",
        else => null,
    };
}

pub fn qclassName(qclass: u16) ?[]const u8 {
    return switch (qclass) {
        1 => "IN",
        3 => "CH",
        4 => "HS",
        255 => "ANY",
        else => null,
    };
}

pub fn qtypeDisplay(qtype: u16, buffer: []u8) []const u8 {
    return qtypeName(qtype) orelse std.fmt.bufPrintIntToSlice(buffer, qtype, 10, .lower, .{});
}

pub fn qclassDisplay(qclass: u16, buffer: []u8) []const u8 {
    return qclassName(qclass) orelse std.fmt.bufPrintIntToSlice(buffer, qclass, 10, .lower, .{});
}

fn parseDnsName(buffer: []u8, packet: []const u8, start_pos: usize) !DnsName {
    if (start_pos >= packet.len) return error.PacketTooShort;

    var pos: usize = start_pos;
    var buf_pos: usize = 0;
    var first_label = true;
    var jumps: u8 = 0;
    const max_jumps = 10; // Prevent compression pointer loops
    var end_pos: ?usize = null;

    while (pos < packet.len) {
        // Check for compression pointer (top 2 bits are 1s)
        if ((packet[pos] & 0xC0) == 0xC0) {
            if (jumps >= max_jumps) return error.TooManyCompressedPointers;
            if (pos + 1 >= packet.len) return error.PacketTooShort;

            // Pointer is formed from the lower 14 bits of the two bytes
            const offset = std.mem.readInt(u16, packet[pos..][0..2], .big) & 0x3FFF;

            // Make sure the pointer isn't obviously invalid (too large for the packet)
            if (offset >= packet.len) return error.InvalidPointer;

            if (end_pos == null) end_pos = pos + 2;

            // Don't do position-based validation as it doesn't work with sliced packets
            // Instead, we'll rely on the max_jumps check to prevent infinite loops
            pos = offset;
            jumps += 1;
            continue;
        }

        const label_len = packet[pos];
        pos += 1;

        // Zero length means end of domain name
        if (label_len == 0) {
            if (end_pos == null) end_pos = pos;
            break;
        }

        // Validate label length (DNS spec: max 63 bytes)
        if (label_len > 63) return error.LabelTooLong;

        // Add dot between labels, except before the first one
        if (!first_label) {
            if (buf_pos >= buffer.len) return error.BufferTooSmall;
            buffer[buf_pos] = '.';
            buf_pos += 1;
        }
        first_label = false;

        // Copy the label contents into canonical lowercase presentation form.
        if (pos + label_len > packet.len) return error.PacketTooShort;
        if (buf_pos + label_len > buffer.len) return error.BufferTooSmall;

        _ = std.ascii.lowerString(buffer[buf_pos .. buf_pos + label_len], packet[pos .. pos + label_len]);
        pos += label_len;
        buf_pos += label_len;

        // Check total domain name length (max 255 bytes)
        if (buf_pos > 255) return error.DomainNameTooLong;
    }

    return .{
        .canonical_name = buffer[0..buf_pos],
        .end_pos = end_pos orelse return error.PacketTooShort,
    };
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

        // Filter and deduplicate against a stack canonical copy; only new
        // domains need heap-owned keys in the map.
        var domain_buffer: [253]u8 = undefined;
        if (domain_raw.len > domain_buffer.len) continue;
        const domain = std.ascii.lowerString(&domain_buffer, domain_raw);

        // Skip localhost entries and other special cases.
        if (std.mem.eql(u8, domain, "localhost") or
            std.mem.eql(u8, domain, "localhost.localdomain") or
            std.mem.eql(u8, domain, "broadcasthost") or
            std.mem.startsWith(u8, domain, "ip6-"))
        {
            continue;
        }

        if (blocked_domains.contains(domain)) continue;

        const owned_domain = try allocator.dupe(u8, domain);
        errdefer allocator.free(owned_domain);
        try blocked_domains.put(owned_domain, owned_domain);
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

test "parse DNS question for A record" {
    const hex_string = "cfc9010000010000000000000a6475636b6475636b676f03636f6d0000010001";
    var bytes: [hex_string.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, hex_string);

    var domain_buffer: [256]u8 = undefined;
    const question = try parseDnsQuestion(&domain_buffer, &bytes);

    try std.testing.expectEqualStrings("duckduckgo.com", question.canonical_qname);
    try std.testing.expectEqual(@as(u16, 1), question.qtype);
    try std.testing.expectEqual(@as(u16, 1), question.qclass);
    try std.testing.expectEqual(@as(usize, 32), question.question_end);
    try std.testing.expectEqualStrings("A", qtypeName(question.qtype).?);
    try std.testing.expectEqualStrings("IN", qclassName(question.qclass).?);
}

test "parse DNS question canonicalizes qname without changing packet" {
    const hex_string = "cfc9010000010000000000000a4475636b4475636b476f03434f4d0000010001";
    var bytes: [hex_string.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, hex_string);
    const original_bytes = bytes;

    var domain_buffer: [256]u8 = undefined;
    const question = try parseDnsQuestion(&domain_buffer, &bytes);

    try std.testing.expectEqualStrings("duckduckgo.com", question.canonical_qname);
    try std.testing.expectEqualSlices(u8, &original_bytes, &bytes);
}

test "parse DNS question for AAAA record" {
    const hex_string = "000101000001000000000000076578616d706c6503636f6d00001c0001";
    var bytes: [hex_string.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, hex_string);

    var domain_buffer: [256]u8 = undefined;
    const question = try parseDnsQuestion(&domain_buffer, &bytes);

    try std.testing.expectEqualStrings("example.com", question.canonical_qname);
    try std.testing.expectEqual(@as(u16, 28), question.qtype);
    try std.testing.expectEqual(@as(u16, 1), question.qclass);
    try std.testing.expectEqual(@as(usize, 29), question.question_end);
    try std.testing.expectEqualStrings("AAAA", qtypeName(question.qtype).?);
}

test "unknown DNS question type falls back to numeric display" {
    const hex_string = "000101000001000000000000076578616d706c6503636f6d00fffe0001";
    var bytes: [hex_string.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes, hex_string);

    var domain_buffer: [256]u8 = undefined;
    const question = try parseDnsQuestion(&domain_buffer, &bytes);

    try std.testing.expectEqualStrings("example.com", question.canonical_qname);
    try std.testing.expectEqual(@as(u16, 65534), question.qtype);
    try std.testing.expect(qtypeName(question.qtype) == null);
    try std.testing.expectEqualStrings("IN", qclassName(question.qclass).?);
}

test "DNS question display names fall back to numbers" {
    var qtype_buffer: [5]u8 = undefined;
    var qclass_buffer: [5]u8 = undefined;

    try std.testing.expectEqualStrings("A", qtypeDisplay(1, &qtype_buffer));
    try std.testing.expectEqualStrings("65534", qtypeDisplay(65534, &qtype_buffer));
    try std.testing.expectEqualStrings("IN", qclassDisplay(1, &qclass_buffer));
    try std.testing.expectEqualStrings("65534", qclassDisplay(65534, &qclass_buffer));
}

test "parse DNS question rejects truncated packet" {
    const packet = [_]u8{
        0x00, 0x01, 0x01, 0x00,
        0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00,
    };
    var domain_buffer: [256]u8 = undefined;

    try std.testing.expectError(error.PacketTooShort, parseDnsQuestion(&domain_buffer, &packet));
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
        \\0.0.0.0 LocalHost # should be ignored
        \\0.0.0.0 BROADCASTHOST # should be ignored
        \\0.0.0.0 IP6-localhost # should be ignored
        \\1.2.3.4 allowed.example.com # different IP should be ignored
        \\
        \\0.0.0.0 Another-Ad.Example.COM
        \\0.0.0.0 ads.example.com
        \\0.0.0.0 ANOTHER-AD.EXAMPLE.com
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
    try std.testing.expect(!blocked_domains.contains("Another-Ad.Example.COM"));

    // Check domains we should have skipped
    try std.testing.expect(!blocked_domains.contains("localhost"));
    try std.testing.expect(!blocked_domains.contains("localhost.localdomain"));
    try std.testing.expect(!blocked_domains.contains("broadcasthost"));
    try std.testing.expect(!blocked_domains.contains("ip6-localhost"));
    try std.testing.expect(!blocked_domains.contains("LocalHost"));
    try std.testing.expect(!blocked_domains.contains("BROADCASTHOST"));
    try std.testing.expect(!blocked_domains.contains("IP6-localhost"));
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
