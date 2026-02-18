const std = @import("std");
const voidbox = @import("voidbox");

// Common paths needed for shell execution (try_ = true to skip missing paths on NixOS etc.)
const shell_base_rules = [_]voidbox.LandlockFsRule{
    .{ .path = "/usr", .access = .read, .try_ = true },
    .{ .path = "/lib", .access = .read, .try_ = true },
    .{ .path = "/lib64", .access = .read, .try_ = true },
    .{ .path = "/bin", .access = .read, .try_ = true },
    .{ .path = "/dev", .access = .read_write },
    .{ .path = "/nix", .access = .read, .try_ = true },
    .{ .path = "/proc", .access = .read },
    .{ .path = "/run", .access = .read, .try_ = true },
};

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    // Test 1: Landlock blocks access to /etc when not in allow list
    std.debug.print("Test 1: Landlock blocks /etc read... ", .{});
    const o1 = try voidbox.launch(.{
        .name = "ll-block",
        .rootfs_path = "/",
        .cmd = &.{ "/bin/sh", "-c", "cat /etc/hostname >/dev/null 2>&1 && exit 1 || exit 0" },
        .isolation = .{ .user = false, .net = false, .mount = false, .pid = false, .uts = false, .ipc = false },
        .security = .{ .landlock = .{ .enabled = true, .fs_rules = &shell_base_rules } },
    }, allocator);
    std.debug.print("{s}\n", .{if (o1.exit_code == 0) "PASS" else "FAIL"});

    // Test 2: Landlock allows /etc when in allow list
    std.debug.print("Test 2: Landlock allows /etc read...  ", .{});
    const o2 = try voidbox.launch(.{
        .name = "ll-allow",
        .rootfs_path = "/",
        .cmd = &.{ "/bin/sh", "-c", "cat /etc/hostname >/dev/null 2>&1" },
        .isolation = .{ .user = false, .net = false, .mount = false, .pid = false, .uts = false, .ipc = false },
        .security = .{ .landlock = .{ .enabled = true, .fs_rules = &(shell_base_rules ++ .{voidbox.LandlockFsRule{ .path = "/etc", .access = .read }}) } },
    }, allocator);
    std.debug.print("{s}\n", .{if (o2.exit_code == 0) "PASS" else "FAIL"});

    // Test 3: Landlock blocks write when only read allowed
    std.debug.print("Test 3: Landlock blocks write to ro.. ", .{});
    const o3 = try voidbox.launch(.{
        .name = "ll-ro",
        .rootfs_path = "/",
        .cmd = &.{ "/bin/sh", "-c", "touch /tmp/ll-test 2>/dev/null && exit 1 || exit 0" },
        .isolation = .{ .user = false, .net = false, .mount = false, .pid = false, .uts = false, .ipc = false },
        .security = .{ .landlock = .{ .enabled = true, .fs_rules = &(shell_base_rules ++ .{voidbox.LandlockFsRule{ .path = "/tmp", .access = .read }}) } },
    }, allocator);
    std.debug.print("{s}\n", .{if (o3.exit_code == 0) "PASS" else "FAIL"});

    const all_pass = o1.exit_code == 0 and o2.exit_code == 0 and o3.exit_code == 0;
    std.debug.print("\n{s}\n", .{if (all_pass) "All Landlock tests passed." else "Some tests FAILED."});
    if (!all_pass) std.posix.exit(1);
}
