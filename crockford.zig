// MIT License
//
// Copyright (c) 2022 LeRoyce Pearson
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// Crockford's Base32 alphabet
pub const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Encode `src` bytes into `dest` as base32 (using Crockford's alphabet).
///
/// Padding is not supported; any extra bits will be set to 0.
pub fn encodeBuf(dest: []u8, src: []const u8) ![]const u8 {
    var fbs = std.io.fixedBufferStream(src);
    var reader = std.io.bitReader(.Big, fbs.reader());

    for (dest) |*c, i| {
        var bits_read: usize = 0;
        const value = try reader.readBits(u5, 5, &bits_read);

        if (bits_read == 0) {
            return dest[0..i];
        }

        c.* = ALPHABET[value << (5 - @intCast(u3, bits_read))];
    }

    {
        var bits_read: usize = undefined;
        _ = try reader.readBits(u5, 5, &bits_read);
        std.debug.assert(bits_read == 0);
    }

    return dest;
}

/// Decode `src` base32 (using Crockford's alphabet) into `dest` buffer.
///
/// Will return `error.NoSpaceLeft` if dest is not long enough. `dest` will
/// be written to by this point.
///
/// Use `calcDecodeDestLen` to get an estimate of how much space will be required.
pub fn decodeBuf(dest: []u8, src: []const u8) ![]const u8 {
    var fbs = std.io.fixedBufferStream(dest);
    var writer = std.io.bitWriter(.Big, fbs.writer());

    for (src) |char| {
        switch (LOOKUP[char]) {
            .Invalid => return error.InvalidCharacter,
            .Ignored => {},
            .Value => |char_val| try writer.writeBits(char_val, 5),
        }
    }
    try writer.flushBits();

    return fbs.getWritten();
}

/// Calculate the bytes needed to decode a given length of base32. The destination length
/// will always be able to fit the given source length.
pub fn calcDecodeDestLen(srcLen: usize) usize {
    return (srcLen * 5 + 7) / 8;
}

/// Calculate the bytes needed to encode a given length of bytes to base32. The destination length
/// will always be able to fit the given source length.
pub fn calcEncodeDestLen(srcLen: usize) usize {
    return (srcLen * 8 + 4) / 5;
}

// Export functions

pub export fn crockford_encodeBuf(destPtr: [*]u8, destLen: usize, srcPtr: [*]const u8, srcLen: usize) isize {
    const dest = destPtr[0..destLen];
    const src = srcPtr[0..srcLen];
    const encoded = encodeBuf(dest, src) catch |err| switch (err) {};
    return @intCast(isize, encoded.len);
}

pub export fn crockford_decodeBuf(destPtr: [*]u8, destLen: usize, srcPtr: [*]const u8, srcLen: usize) isize {
    const dest = destPtr[0..destLen];
    const src = srcPtr[0..srcLen];
    const decoded = decodeBuf(dest, src) catch |err| return switch (err) {
        error.InvalidCharacter => -1,
        error.NoSpaceLeft => -2,
    };
    return @intCast(isize, decoded.len);
}

pub export fn crockford_calcDecodeDestLen(srcLen: usize) usize {
    return calcDecodeDestLen(srcLen);
}

pub export fn crockford_calcEncodeDestLen(srcLen: usize) usize {
    return calcEncodeDestLen(srcLen);
}

// Lookup table for decoding
const LOOKUP = gen_lookup_table: {
    const CharType = union(enum) {
        Invalid: void,
        Ignored: void,
        Value: u5,
    };
    var lookup = [1]CharType{.Invalid} ** 256;
    for (ALPHABET) |char, idx| {
        lookup[char] = .{ .Value = idx };
        lookup[std.ascii.toLower(char)] = .{ .Value = idx };
    }

    lookup['O'] = .{ .Value = 0 };
    lookup['o'] = .{ .Value = 0 };

    lookup['I'] = .{ .Value = 1 };
    lookup['i'] = .{ .Value = 1 };
    lookup['L'] = .{ .Value = 1 };
    lookup['l'] = .{ .Value = 1 };
    lookup['-'] = .Ignored;

    break :gen_lookup_table lookup;
};

// Implement a simple command line tool to encode stdin to base32
const std = @import("std");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};

    const Options = struct {
        decode: bool = false,
    };
    const args = try std.process.argsAlloc(gpa.allocator());
    var options = Options{};
    for (args[1..]) |arg| {
        if (std.mem.eql(u8, arg, "-d")) {
            options.decode = true;
        } else {
            try std.io.getStdErr().writer().print(
                \\Unknown option '{}'
                \\
                \\USAGE
                \\	crockford [OPTION]...
                \\
                \\DESCRIPTION
                \\	Base32 encode or decode standard input to standard output using Crockford's Base32 Alphabet.
                \\
                \\	-d
                \\		decode data
            , .{std.zig.fmtEscapes(arg)});
            std.process.exit(1);
        }
    }

    const input = try std.io.getStdIn().readToEndAlloc(gpa.allocator(), 10_000_000);

    if (options.decode) {
        const decode_buf = try gpa.allocator().alloc(u8, calcDecodeDestLen(input.len));
        try std.io.getStdOut().writeAll(
            try decodeBuf(decode_buf, input),
        );
    } else {
        const encode_buf = try gpa.allocator().alloc(u8, calcEncodeDestLen(input.len));
        try std.io.getStdOut().writeAll(
            try encodeBuf(encode_buf, input),
        );
    }
}

// Tests
test "calculate decoded length" {
    try std.testing.expectEqual(@as(usize, 0), calcDecodeDestLen(0));
    try std.testing.expectEqual(@as(usize, 1), calcDecodeDestLen(1));
    try std.testing.expectEqual(@as(usize, 17), calcDecodeDestLen(26));
}

test "calculate encoded length" {
    try std.testing.expectEqual(@as(usize, 0), calcEncodeDestLen(0));
    try std.testing.expectEqual(@as(usize, 2), calcEncodeDestLen(1));
    try std.testing.expectEqual(@as(usize, 26), calcEncodeDestLen(16));
}

fn testDecode(expected: []const u8, encoded: []const u8) !void {
    errdefer {
        std.log.err("expected = {}", .{std.fmt.fmtSliceHexUpper(expected)});
        std.log.err("encoded = {}", .{std.zig.fmtEscapes(encoded)});
    }

    const dest = try std.testing.allocator.alloc(u8, calcDecodeDestLen(encoded.len));
    defer std.testing.allocator.free(dest);

    const decoded = try decodeBuf(dest, encoded);
    errdefer {
        std.log.err("decoded = {}", .{std.fmt.fmtSliceHexUpper(decoded)});
    }

    try std.testing.expectEqualSlices(u8, expected, decoded);
}

test "decode from base32" {
    try testDecode("hello\n\x00", "D1JPRV3F18");
    try testDecode("hello", "D1JPRV3F");
    try testDecode(&[_]u8{0b0000_1000}, "1");
    try testDecode(&[_]u8{ 0, 0b0100_0000 }, "01");
}

fn testEncode(bytes: []const u8, expected: []const u8) !void {
    errdefer {
        std.log.err("expected = \"{}\"", .{std.zig.fmtEscapes(expected)});
        std.log.err("bytes = \"{}\"", .{std.zig.fmtEscapes(bytes)});
    }

    // Encode
    const encode_buf = try std.testing.allocator.alloc(u8, calcEncodeDestLen(bytes.len));
    defer std.testing.allocator.free(encode_buf);

    const encoded = try encodeBuf(encode_buf, bytes);
    errdefer std.log.err("encoded = \"{}\"", .{std.zig.fmtEscapes(encoded)});

    try std.testing.expectEqualSlices(u8, expected, encoded);
}

test "encode string" {
    try testEncode(&([_]u8{0xFF} ** 16), "ZZZZZZZZZZZZZZZZZZZZZZZZZW");
    try testEncode("hello", "D1JPRV3F");
    try testEncode("hello\n", "D1JPRV3F18");
}

fn testEncodeDecodeString(text: []const u8) !void {
    errdefer std.log.err("text = \"{}\"", .{std.zig.fmtEscapes(text)});

    // Encode
    const encode_buf = try std.testing.allocator.alloc(u8, calcEncodeDestLen(text.len));
    defer std.testing.allocator.free(encode_buf);

    const encoded = try encodeBuf(encode_buf, text);
    errdefer std.log.err("encoded = \"{}\"", .{std.zig.fmtEscapes(encoded)});

    // Decode
    const decode_buf = try std.testing.allocator.alloc(u8, calcDecodeDestLen(encoded.len));
    defer std.testing.allocator.free(decode_buf);

    const decoded = try decodeBuf(decode_buf, encoded);
    errdefer std.log.err("decoded = \"{}\"", .{std.zig.fmtEscapes(decoded)});

    try std.testing.expectEqualSlices(u8, text, decoded[0..text.len]);
}

test "encode string then get the same string back from base32" {
    try testEncodeDecodeString("hello");
    try testEncodeDecodeString("hello\n");
    try testEncodeDecodeString("hello, world");
}

fn testExportedAPIDecode(expected: []const u8, encoded: []const u8) !void {
    const dest = try std.testing.allocator.alloc(u8, crockford_calcDecodeDestLen(encoded.len));
    defer std.testing.allocator.free(dest);

    const n = crockford_decodeBuf(dest.ptr, dest.len, encoded.ptr, encoded.len);
    if (n < 0) {
        return error.Unknown;
    }
    try std.testing.expectEqual(expected.len, @intCast(usize, n));

    const decoded = dest[0..@intCast(usize, n)];
    try std.testing.expectEqualSlices(u8, expected, decoded);
}

test "decode from base32" {
    try testExportedAPIDecode("hello\n\x00", "D1JPRV3F18");
    try testExportedAPIDecode("hello", "D1JPRV3F");
    try testExportedAPIDecode(&[_]u8{0b0000_1000}, "1");
    try testExportedAPIDecode(&[_]u8{ 0, 0b0100_0000 }, "01");
}

fn testExportedAPIEncode(bytes: []const u8, expected: []const u8) !void {
    const encode_buf = try std.testing.allocator.alloc(u8, crockford_calcEncodeDestLen(bytes.len));
    defer std.testing.allocator.free(encode_buf);

    const n = crockford_encodeBuf(encode_buf.ptr, encode_buf.len, bytes.ptr, bytes.len);
    if (n < 0) {
        return error.Unknown;
    }
    try std.testing.expectEqual(expected.len, @intCast(usize, n));

    const encoded = encode_buf[0..@intCast(usize, n)];
    try std.testing.expectEqualSlices(u8, expected, encoded);
}

test "encode string using exported functions" {
    try testExportedAPIEncode(&([_]u8{0xFF} ** 16), "ZZZZZZZZZZZZZZZZZZZZZZZZZW");
    try testExportedAPIEncode("hello", "D1JPRV3F");
    try testExportedAPIEncode("hello\n", "D1JPRV3F18");
}
