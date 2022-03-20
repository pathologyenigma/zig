const CodeSignature = @This();

const std = @import("std");
const assert = std.debug.assert;
const fs = std.fs;
const log = std.log.scoped(.link);
const macho = std.macho;
const mem = std.mem;
const testing = std.testing;
const Allocator = mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;

const hash_size: u8 = 32;

const Blob = union(enum) {
    code_directory: CodeDirectory,
    requirements: Requirements,
    entitlements: Entitlements,
    signature: Signature,

    fn deinit(self: *Blob, allocator: Allocator) void {
        switch (self.*) {
            .code_directory => |*x| x.deinit(allocator),
            .requirements => |*x| x.deinit(allocator),
            .entitlements => |*x| x.deinit(allocator),
            .signature => |*x| x.deinit(allocator),
        }
    }

    fn slotType(self: Blob) u32 {
        return switch (self) {
            .code_directory => |x| x.slotType(),
            .requirements => |x| x.slotType(),
            .entitlements => |x| x.slotType(),
            .signature => |x| x.slotType(),
        };
    }

    fn size(self: Blob) u32 {
        return switch (self) {
            .code_directory => |x| x.size(),
            .requirements => |x| x.size(),
            .entitlements => |x| x.size(),
            .signature => |x| x.size(),
        };
    }

    fn write(self: Blob, writer: anytype) !void {
        return switch (self) {
            .code_directory => |x| x.write(writer),
            .requirements => |x| x.write(writer),
            .entitlements => |x| x.write(writer),
            .signature => |x| x.write(writer),
        };
    }
};

const CodeDirectory = struct {
    inner: macho.CodeDirectory,
    ident: std.ArrayListUnmanaged(u8) = .{},
    special_slots: [n_special_slots][hash_size]u8,
    code_slots: std.ArrayListUnmanaged([hash_size]u8) = .{},

    const n_special_slots: usize = 7;

    fn init(page_size: u16) CodeDirectory {
        var cdir: CodeDirectory = .{
            .inner = .{
                .magic = macho.CSMAGIC_CODEDIRECTORY,
                .length = @sizeOf(macho.CodeDirectory),
                .version = macho.CS_SUPPORTSEXECSEG,
                .flags = macho.CS_ADHOC,
                .hashOffset = 0,
                .identOffset = @sizeOf(macho.CodeDirectory),
                .nSpecialSlots = n_special_slots,
                .nCodeSlots = 0,
                .codeLimit = 0,
                .hashSize = hash_size,
                .hashType = macho.CS_HASHTYPE_SHA256,
                .platform = 0,
                .pageSize = @truncate(u8, std.math.log2(page_size)),
                .spare2 = 0,
                .scatterOffset = 0,
                .teamOffset = 0,
                .spare3 = 0,
                .codeLimit64 = 0,
                .execSegBase = 0,
                .execSegLimit = 0,
                .execSegFlags = 0,
            },
            .special_slots = undefined,
        };
        comptime var i = 0;
        inline while (i < n_special_slots) : (i += 1) {
            cdir.special_slots[i] = [_]u8{0} ** hash_size;
            cdir.inner.length += hash_size;
        }
        return cdir;
    }

    fn deinit(self: *CodeDirectory, allocator: Allocator) void {
        self.ident.deinit(allocator);
        self.code_slots.deinit(allocator);
    }

    fn addIdentity(self: *CodeDirectory, allocator: Allocator, ident: []const u8) !void {
        try self.ident.ensureTotalCapacityPrecise(allocator, ident.len + 1);
        self.ident.appendSliceAssumeCapacity(ident);
        self.ident.appendAssumeCapacity(0);
        self.inner.length += @intCast(u32, self.ident.items.len);
        self.inner.hashOffset = self.inner.length;
    }

    fn addSpecialHash(self: *CodeDirectory, index: u32, hash: [hash_size]u8) void {
        assert(index > 0);
        // self.inner.nSpecialSlots = std.math.max(self.inner.nSpecialSlots, index);
        mem.copy(u8, &self.special_slots[index - 1], &hash);
    }

    fn slotType(self: CodeDirectory) u32 {
        _ = self;
        return macho.CSSLOT_CODEDIRECTORY;
    }

    fn size(self: CodeDirectory) u32 {
        return self.inner.length;
    }

    fn write(self: CodeDirectory, writer: anytype) !void {
        try writer.writeIntBig(u32, self.inner.magic);
        try writer.writeIntBig(u32, self.inner.length);
        try writer.writeIntBig(u32, self.inner.version);
        try writer.writeIntBig(u32, self.inner.flags);
        try writer.writeIntBig(u32, self.inner.hashOffset);
        try writer.writeIntBig(u32, self.inner.identOffset);
        try writer.writeIntBig(u32, self.inner.nSpecialSlots);
        try writer.writeIntBig(u32, self.inner.nCodeSlots);
        try writer.writeIntBig(u32, self.inner.codeLimit);
        try writer.writeByte(self.inner.hashSize);
        try writer.writeByte(self.inner.hashType);
        try writer.writeByte(self.inner.platform);
        try writer.writeByte(self.inner.pageSize);
        try writer.writeIntBig(u32, self.inner.spare2);
        try writer.writeIntBig(u32, self.inner.scatterOffset);
        try writer.writeIntBig(u32, self.inner.teamOffset);
        try writer.writeIntBig(u32, self.inner.spare3);
        try writer.writeIntBig(u64, self.inner.codeLimit64);
        try writer.writeIntBig(u64, self.inner.execSegBase);
        try writer.writeIntBig(u64, self.inner.execSegLimit);
        try writer.writeIntBig(u64, self.inner.execSegFlags);

        try writer.writeAll(self.ident.items);

        var i: isize = n_special_slots;
        while (i > 0) : (i -= 1) {
            try writer.writeAll(&self.special_slots[@intCast(usize, i - 1)]);
        }

        for (self.code_slots.items) |slot| {
            try writer.writeAll(&slot);
        }
    }
};

const Requirements = struct {
    fn deinit(self: *Requirements, allocator: Allocator) void {
        _ = self;
        _ = allocator;
    }

    fn slotType(self: Requirements) u32 {
        _ = self;
        return macho.CSSLOT_REQUIREMENTS;
    }

    fn size(self: Requirements) u32 {
        _ = self;
        return 3 * @sizeOf(u32);
    }

    fn write(self: Requirements, writer: anytype) !void {
        try writer.writeIntBig(u32, macho.CSMAGIC_REQUIREMENTS);
        try writer.writeIntBig(u32, self.size());
        try writer.writeIntBig(u32, 0);
    }
};

const Entitlements = struct {
    inner: []const u8,

    fn clone(self: Entitlements, allocator: Allocator) !Entitlements {
        var inner = try allocator.dupe(u8, self.inner);
        return Entitlements{ .inner = inner };
    }

    fn deinit(self: *Entitlements, allocator: Allocator) void {
        allocator.free(self.inner);
    }

    fn slotType(self: Entitlements) u32 {
        _ = self;
        return macho.CSSLOT_ENTITLEMENTS;
    }

    fn size(self: Entitlements) u32 {
        return @intCast(u32, self.inner.len) + 2 * @sizeOf(u32);
    }

    fn write(self: Entitlements, writer: anytype) !void {
        try writer.writeIntBig(u32, macho.CSMAGIC_EMBEDDED_ENTITLEMENTS);
        try writer.writeIntBig(u32, self.size());
        try writer.writeAll(self.inner);
    }
};

const Signature = struct {
    fn deinit(self: *Signature, allocator: Allocator) void {
        _ = self;
        _ = allocator;
    }

    fn slotType(self: Signature) u32 {
        _ = self;
        return macho.CSSLOT_SIGNATURESLOT;
    }

    fn size(self: Signature) u32 {
        _ = self;
        return 2 * @sizeOf(u32);
    }

    fn write(self: Signature, writer: anytype) !void {
        try writer.writeIntBig(u32, macho.CSMAGIC_BLOBWRAPPER);
        try writer.writeIntBig(u32, self.size());
    }
};

entitlements: ?Entitlements = null,

/// Code signature blob header.
inner: macho.SuperBlob = .{
    .magic = macho.CSMAGIC_EMBEDDED_SIGNATURE,
    .length = @sizeOf(macho.SuperBlob),
    .count = 0,
},

blobs: std.ArrayListUnmanaged(Blob) = .{},

pub fn addEntitlements(self: *CodeSignature, allocator: Allocator, path: []const u8) !void {
    const file = try fs.cwd().openFile(path, .{});
    defer file.close();
    const inner = try file.readToEndAlloc(allocator, std.math.maxInt(u32));
    self.entitlements = .{ .inner = inner };
}

pub fn calcAdhocSignature(
    self: *CodeSignature,
    allocator: Allocator,
    file: fs.File,
    id: []const u8,
    text_segment: macho.segment_command_64,
    code_sig_cmd: macho.linkedit_data_command,
    output_mode: std.builtin.OutputMode,
    page_size: u16,
) !void {
    var cdir = CodeDirectory.init(page_size);
    cdir.inner.execSegBase = text_segment.fileoff;
    cdir.inner.execSegLimit = text_segment.filesize;
    cdir.inner.execSegFlags = if (output_mode == .Exe) macho.CS_EXECSEG_MAIN_BINARY else 0;
    const file_size = code_sig_cmd.dataoff;
    cdir.inner.codeLimit = file_size;

    // 1. Save the identifier and update offsets
    try cdir.addIdentity(allocator, id);

    const total_pages = mem.alignForward(file_size, page_size) / page_size;

    var buffer = try allocator.alloc(u8, page_size);
    defer allocator.free(buffer);

    try cdir.code_slots.ensureTotalCapacityPrecise(allocator, total_pages);

    // 2. Calculate hash for each page (in file) and write it to the buffer
    // TODO figure out how we can cache several hashes since we won't update
    // every page during incremental linking
    var hash: [hash_size]u8 = undefined;
    var i: usize = 0;
    while (i < total_pages) : (i += 1) {
        const fstart = i * page_size;
        const fsize = if (fstart + page_size > file_size) file_size - fstart else page_size;
        const len = try file.preadAll(buffer, fstart);
        assert(fsize <= len);

        Sha256.hash(buffer[0..fsize], &hash, .{});

        cdir.code_slots.appendAssumeCapacity(hash);
        cdir.inner.nCodeSlots += 1;
        cdir.inner.length += hash_size;
    }

    const cdir_ptr = try self.blobs.addOne(allocator);
    cdir_ptr.* = .{ .code_directory = cdir };
    // try self.blobs.append(allocator, .{ .code_directory = cdir });
    self.inner.length += @sizeOf(macho.BlobIndex) + cdir.inner.length;
    self.inner.count += 1;

    // 2. Create Requirements blob
    var req: Requirements = .{};
    {
        var buf = std.ArrayList(u8).init(allocator);
        defer buf.deinit();
        try req.write(buf.writer());
        Sha256.hash(buf.items, &hash, .{});
        cdir_ptr.code_directory.addSpecialHash(req.slotType(), hash);
    }
    try self.blobs.append(allocator, .{ .requirements = req });
    self.inner.count += 1;
    self.inner.length += @sizeOf(macho.BlobIndex) + req.size();

    // 3. Create Entitlements blob
    if (self.entitlements) |ents| {
        var buf = std.ArrayList(u8).init(allocator);
        defer buf.deinit();
        try ents.write(buf.writer());
        Sha256.hash(buf.items, &hash, .{});
        cdir_ptr.code_directory.addSpecialHash(ents.slotType(), hash);

        try self.blobs.append(allocator, .{ .entitlements = try ents.clone(allocator) });
        self.inner.count += 1;
        self.inner.length += @sizeOf(macho.BlobIndex) + ents.size();
    }

    // 4. Create empty Signature blob
    var sig: Signature = .{};
    try self.blobs.append(allocator, .{ .signature = sig });
    self.inner.count += 1;
    self.inner.length += @sizeOf(macho.BlobIndex) + sig.size();
}

pub fn size(self: CodeSignature) u32 {
    return self.inner.length;
}

pub fn write(self: CodeSignature, writer: anytype) !void {
    try self.writeHeader(writer);
    var offset: u32 = @sizeOf(macho.SuperBlob) + @sizeOf(macho.BlobIndex) * @intCast(u32, self.blobs.items.len);
    for (self.blobs.items) |blob| {
        try writer.writeIntBig(u32, blob.slotType());
        try writer.writeIntBig(u32, offset);
        offset += blob.size();
    }
    for (self.blobs.items) |blob| {
        try blob.write(writer);
    }
}

pub fn reset(self: *CodeSignature, allocator: Allocator) void {
    self.inner.count = 0;
    for (self.blobs.items) |*blob| {
        blob.deinit(allocator);
    }
    self.blobs.clearAndFree(allocator);
}

pub fn deinit(self: *CodeSignature, allocator: Allocator) void {
    for (self.blobs.items) |*blob| {
        blob.deinit(allocator);
    }
    self.blobs.deinit(allocator);
    if (self.entitlements) |*ents| {
        ents.deinit(allocator);
    }
}

fn writeHeader(self: CodeSignature, writer: anytype) !void {
    try writer.writeIntBig(u32, self.inner.magic);
    try writer.writeIntBig(u32, self.inner.length);
    try writer.writeIntBig(u32, self.inner.count);
}

test "CodeSignature header" {
    var code_sig: CodeSignature = .{};
    defer code_sig.deinit(testing.allocator);

    var buffer: [@sizeOf(macho.SuperBlob)]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);
    try code_sig.writeHeader(stream.writer());

    const expected = &[_]u8{ 0xfa, 0xde, 0x0c, 0xc0, 0x0, 0x0, 0x0, 0xc, 0x0, 0x0, 0x0, 0x0 };
    try testing.expect(mem.eql(u8, expected, &buffer));
}

pub fn calcCodeSignaturePaddingSize(id: []const u8, file_size: u64, page_size: u16) u32 {
    const ident_size = id.len + 1;
    const total_pages = mem.alignForwardGeneric(u64, file_size, page_size) / page_size;
    const hashed_size = total_pages * hash_size;
    const codesig_header: u32 = @sizeOf(macho.SuperBlob) + 4 * @sizeOf(macho.BlobIndex) + @sizeOf(macho.CodeDirectory) + 0x4000;
    return @intCast(u32, mem.alignForwardGeneric(u64, codesig_header + ident_size + hashed_size, @sizeOf(u64)));
}
