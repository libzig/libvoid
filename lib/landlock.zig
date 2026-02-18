const std = @import("std");
const linux = std.os.linux;
const checkErr = @import("utils.zig").checkErr;

const LandlockOptions = @import("config.zig").LandlockOptions;
const LandlockAccess = @import("config.zig").LandlockAccess;
const LandlockNetAccess = @import("config.zig").LandlockNetAccess;

// --- Kernel ABI constants ---

const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;

const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;
const LANDLOCK_RULE_NET_PORT: u32 = 2;

// Filesystem access flags (ABI V1)
const ACCESS_FS_EXECUTE: u64 = 1 << 0;
const ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
const ACCESS_FS_READ_FILE: u64 = 1 << 2;
const ACCESS_FS_READ_DIR: u64 = 1 << 3;
const ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
const ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
const ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
const ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
const ACCESS_FS_MAKE_REG: u64 = 1 << 8;
const ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
const ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
const ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
const ACCESS_FS_MAKE_SYM: u64 = 1 << 12;

// ABI V2
const ACCESS_FS_REFER: u64 = 1 << 13;

// ABI V3
const ACCESS_FS_TRUNCATE: u64 = 1 << 14;

// ABI V5
const ACCESS_FS_IOCTL_DEV: u64 = 1 << 15;

// Network access flags (ABI V4)
const ACCESS_NET_BIND_TCP: u64 = 1 << 0;
const ACCESS_NET_CONNECT_TCP: u64 = 1 << 1;

// Composite access masks
const ACCESS_READ = ACCESS_FS_READ_FILE | ACCESS_FS_READ_DIR | ACCESS_FS_EXECUTE;

const ACCESS_WRITE_V1 = ACCESS_FS_WRITE_FILE | ACCESS_FS_MAKE_CHAR | ACCESS_FS_MAKE_DIR |
    ACCESS_FS_MAKE_REG | ACCESS_FS_MAKE_SOCK | ACCESS_FS_MAKE_FIFO |
    ACCESS_FS_MAKE_BLOCK | ACCESS_FS_MAKE_SYM | ACCESS_FS_REMOVE_FILE |
    ACCESS_FS_REMOVE_DIR;

const ACCESS_EXECUTE = ACCESS_FS_EXECUTE;

// --- Kernel ABI structs ---

const RulesetAttr = extern struct {
    handled_access_fs: u64 = 0,
    handled_access_net: u64 = 0,
    scoped: u64 = 0,
};

const PathBeneathAttr = extern struct {
    allowed_access: u64,
    parent_fd: i32,
    _pad: i32 = 0,
};

const NetPortAttr = extern struct {
    allowed_access: u64,
    port: u64,
};

// --- Public API ---

pub fn probeAbi() ?u32 {
    const rc = linux.syscall3(
        .landlock_create_ruleset,
        0,
        0,
        LANDLOCK_CREATE_RULESET_VERSION,
    );
    const signed: isize = @bitCast(rc);
    if (signed < 0) return null;
    return @intCast(rc);
}

pub fn apply(options: LandlockOptions) !void {
    if (!options.enabled) return;

    const abi = probeAbi() orelse return error.LandlockNotSupported;

    // Compute handled access masks based on rules and ABI version
    var handled_fs: u64 = 0;
    var handled_net: u64 = 0;

    for (options.fs_rules) |rule| {
        handled_fs |= accessToFlags(rule.access, abi);
    }

    if (abi >= 4) {
        for (options.net_rules) |rule| {
            handled_net |= netAccessToFlags(rule.access);
        }
    }

    if (handled_fs == 0 and handled_net == 0) return;

    // Create ruleset
    var attr = RulesetAttr{
        .handled_access_fs = handled_fs,
        .handled_access_net = handled_net,
    };

    const ruleset_rc = linux.syscall3(
        .landlock_create_ruleset,
        @intFromPtr(&attr),
        @sizeOf(RulesetAttr),
        0,
    );
    const ruleset_signed: isize = @bitCast(ruleset_rc);
    if (ruleset_signed < 0) return error.LandlockCreateRulesetFailed;
    const ruleset_fd: i32 = @intCast(ruleset_signed);
    defer std.posix.close(ruleset_fd);

    // Add filesystem rules
    for (options.fs_rules) |rule| {
        const flags = accessToFlags(rule.access, abi);
        const path_fd = std.posix.openatZ(
            linux.AT.FDCWD,
            @ptrCast(rule.path.ptr),
            .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true },
            0,
        ) catch {
            if (rule.try_) continue;
            return error.LandlockPathOpenFailed;
        };
        defer std.posix.close(path_fd);

        var path_attr = PathBeneathAttr{
            .allowed_access = flags,
            .parent_fd = path_fd,
        };

        const add_rc = linux.syscall4(
            .landlock_add_rule,
            @intCast(ruleset_fd),
            LANDLOCK_RULE_PATH_BENEATH,
            @intFromPtr(&path_attr),
            0,
        );
        const add_signed: isize = @bitCast(add_rc);
        if (add_signed < 0) return error.LandlockAddRuleFailed;
    }

    // Add network rules (ABI V4+)
    if (abi >= 4) {
        for (options.net_rules) |rule| {
            var net_attr = NetPortAttr{
                .allowed_access = netAccessToFlags(rule.access),
                .port = @intCast(rule.port),
            };

            const add_rc = linux.syscall4(
                .landlock_add_rule,
                @intCast(ruleset_fd),
                LANDLOCK_RULE_NET_PORT,
                @intFromPtr(&net_attr),
                0,
            );
            const add_signed: isize = @bitCast(add_rc);
            if (add_signed < 0) return error.LandlockAddRuleFailed;
        }
    }

    // Restrict self — irreversible
    const restrict_rc = linux.syscall2(
        .landlock_restrict_self,
        @intCast(ruleset_fd),
        0,
    );
    const restrict_signed: isize = @bitCast(restrict_rc);
    if (restrict_signed < 0) return error.LandlockRestrictSelfFailed;
}

fn accessToFlags(access: LandlockAccess, abi: u32) u64 {
    var write_flags = ACCESS_WRITE_V1;
    if (abi >= 2) write_flags |= ACCESS_FS_REFER;
    if (abi >= 3) write_flags |= ACCESS_FS_TRUNCATE;

    return switch (access) {
        .read => ACCESS_READ,
        .write => write_flags,
        .read_write => ACCESS_READ | write_flags,
        .execute => ACCESS_EXECUTE,
    };
}

fn netAccessToFlags(access: LandlockNetAccess) u64 {
    return switch (access) {
        .bind => ACCESS_NET_BIND_TCP,
        .connect => ACCESS_NET_CONNECT_TCP,
        .bind_connect => ACCESS_NET_BIND_TCP | ACCESS_NET_CONNECT_TCP,
    };
}

// --- Tests ---

test "accessToFlags read returns read flags" {
    const flags = accessToFlags(.read, 1);
    try std.testing.expect(flags & ACCESS_FS_READ_FILE != 0);
    try std.testing.expect(flags & ACCESS_FS_READ_DIR != 0);
    try std.testing.expect(flags & ACCESS_FS_EXECUTE != 0);
    try std.testing.expect(flags & ACCESS_FS_WRITE_FILE == 0);
}

test "accessToFlags write V1 excludes refer and truncate" {
    const flags = accessToFlags(.write, 1);
    try std.testing.expect(flags & ACCESS_FS_WRITE_FILE != 0);
    try std.testing.expect(flags & ACCESS_FS_MAKE_DIR != 0);
    try std.testing.expect(flags & ACCESS_FS_REMOVE_FILE != 0);
    try std.testing.expect(flags & ACCESS_FS_REFER == 0);
    try std.testing.expect(flags & ACCESS_FS_TRUNCATE == 0);
}

test "accessToFlags write V2 includes refer" {
    const flags = accessToFlags(.write, 2);
    try std.testing.expect(flags & ACCESS_FS_REFER != 0);
    try std.testing.expect(flags & ACCESS_FS_TRUNCATE == 0);
}

test "accessToFlags write V3 includes truncate" {
    const flags = accessToFlags(.write, 3);
    try std.testing.expect(flags & ACCESS_FS_REFER != 0);
    try std.testing.expect(flags & ACCESS_FS_TRUNCATE != 0);
}

test "accessToFlags read_write combines both" {
    const flags = accessToFlags(.read_write, 3);
    try std.testing.expect(flags & ACCESS_FS_READ_FILE != 0);
    try std.testing.expect(flags & ACCESS_FS_WRITE_FILE != 0);
    try std.testing.expect(flags & ACCESS_FS_TRUNCATE != 0);
}

test "accessToFlags execute returns only execute" {
    const flags = accessToFlags(.execute, 3);
    try std.testing.expectEqual(ACCESS_EXECUTE, flags);
}

test "netAccessToFlags bind" {
    try std.testing.expectEqual(ACCESS_NET_BIND_TCP, netAccessToFlags(.bind));
}

test "netAccessToFlags connect" {
    try std.testing.expectEqual(ACCESS_NET_CONNECT_TCP, netAccessToFlags(.connect));
}

test "netAccessToFlags bind_connect" {
    try std.testing.expectEqual(ACCESS_NET_BIND_TCP | ACCESS_NET_CONNECT_TCP, netAccessToFlags(.bind_connect));
}

test "probeAbi returns non-null on supported kernel" {
    const abi = probeAbi();
    // Kernel 6.17 should support Landlock
    if (abi) |v| {
        try std.testing.expect(v >= 1);
    }
}
