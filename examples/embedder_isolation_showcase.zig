const std = @import("std");
const libvoid = @import("libvoid");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("=== Libvoid Isolation Mechanisms Showcase ===\n\n", .{});

    // 1. Demonstrate chroot
    std.debug.print("1. Using chroot (legacy):\n", .{});
    const config_chroot = libvoid.JailConfig{
        .name = "chroot-demo",
        .rootfs_path = "/",
        .cmd = &.{ "/bin/echo", "  Running with chroot isolation" },
        .runtime = .{ .use_pivot_root = false }, // Use chroot explicitly
        .isolation = .{
            .user = true,
            .net = false,
            .mount = true,
            .pid = false,
            .uts = false,
            .ipc = false,
            .cgroup = false,
        },
        .fs_actions = &.{
            .{ .proc = "/proc" },
            .{ .dev = "/dev" },
        },
    };
    const outcome1 = try libvoid.launch(config_chroot, allocator);
    std.debug.print("  Exit code: {d}\n\n", .{outcome1.exit_code});

    // 2. Demonstrate pivot_root
    std.debug.print("2. Using pivot_root (secure, modern - DEFAULT):\n", .{});
    const config_pivot = libvoid.JailConfig{
        .name = "pivot-demo",
        .rootfs_path = "/",
        .cmd = &.{ "/bin/echo", "  Running with pivot_root isolation" },
        .runtime = .{ .use_pivot_root = true }, // Use pivot_root (this is the default)
        .isolation = .{
            .user = true,
            .net = false,
            .mount = true,
            .pid = false,
            .uts = false,
            .ipc = false,
            .cgroup = false,
        },
        .fs_actions = &.{
            .{ .proc = "/proc" },
            .{ .dev = "/dev" },
        },
    };
    const outcome2 = try libvoid.launch(config_pivot, allocator);
    std.debug.print("  Exit code: {d}\n\n", .{outcome2.exit_code});

    // 3. Demonstrate bind mounts
    std.debug.print("3. Using bind mounts:\n", .{});
    const config_bind = libvoid.JailConfig{
        .name = "bind-demo",
        .rootfs_path = "/",
        .cmd = &.{ "/bin/sh", "-c", "echo '  Bind mount demo:' && ls /host-usr/bin | head -n 5" },
        .isolation = .{
            .user = true,
            .net = false,
            .mount = true,
            .pid = false,
            .uts = false,
            .ipc = false,
            .cgroup = false,
        },
        .fs_actions = &.{
            .{ .ro_bind = .{ .src = "/usr", .dest = "/host-usr" } },
            .{ .bind = .{ .src = "/tmp", .dest = "/tmp" } },
            .{ .proc = "/proc" },
            .{ .dev = "/dev" },
        },
    };
    const outcome3 = try libvoid.launch(config_bind, allocator);
    std.debug.print("  Exit code: {d}\n\n", .{outcome3.exit_code});

    // 4. Demonstrate tmpfs
    std.debug.print("4. Using tmpfs (in-memory filesystem):\n", .{});
    const config_tmpfs = libvoid.JailConfig{
        .name = "tmpfs-demo",
        .rootfs_path = "/",
        .cmd = &.{ "/bin/sh", "-c", "echo '  Writing to tmpfs...' && echo 'test data' > /my-tmpfs/test.txt && cat /my-tmpfs/test.txt" },
        .isolation = .{
            .user = true,
            .net = false,
            .mount = true,
            .pid = false,
            .uts = false,
            .ipc = false,
            .cgroup = false,
        },
        .fs_actions = &.{
            .{ .tmpfs = .{ .dest = "/my-tmpfs" } },
            .{ .proc = "/proc" },
            .{ .dev = "/dev" },
        },
    };
    const outcome4 = try libvoid.launch(config_tmpfs, allocator);
    std.debug.print("  Exit code: {d}\n\n", .{outcome4.exit_code});

    std.debug.print("=== All demonstrations complete ===\n", .{});
    std.debug.print("\nKey Takeaways:\n", .{});
    std.debug.print("  - pivot_root (demo 2) is more secure than chroot (demo 1)\n", .{});
    std.debug.print("  - pivot_root is the DEFAULT - you only need --chroot for legacy compatibility\n", .{});
    std.debug.print("  - Bind mounts (demo 3) let you selectively expose host directories\n", .{});
    std.debug.print("  - tmpfs (demo 4) provides fast in-memory storage\n", .{});
}
