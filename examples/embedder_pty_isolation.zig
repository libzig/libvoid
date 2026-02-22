const std = @import("std");
const libvoid = @import("libvoid");
const linux = std.os.linux;
const posix = std.posix;

pub fn main() !void {
    const allocator = std.heap.c_allocator;

    try runTest(allocator, "SANDBOX", .{
        .user = true,
        .net = false,
        .mount = true,
        .pid = true,
        .uts = true,
        .ipc = true,
        .cgroup = false,
    });
}

fn runTest(allocator: std.mem.Allocator, label: []const u8, iso: libvoid.IsolationOptions) !void {
    std.debug.print("\n{s}...\n", .{label});

    const config = libvoid.JailConfig{
        .name = "pty-sandbox",
        .rootfs_path = "/",
        .cmd = &.{"/bin/sh"},
        .isolation = iso,
        .runtime = .{
            .use_pivot_root = false,
            .hostname = if (iso.uts) "sandbox" else null,
        },
        .security = .{
            .no_new_privs = true,
            .seccomp_mode = .disabled,
        },
        .fs_actions = if (iso.mount) &.{
            .{ .ro_bind = .{ .src = "/usr", .dest = "/usr" } },
            .{ .ro_bind = .{ .src = "/lib", .dest = "/lib" } },
            .{ .ro_bind = .{ .src = "/lib64", .dest = "/lib64" } },
            .{ .ro_bind = .{ .src = "/bin", .dest = "/bin" } },
            .{ .ro_bind = .{ .src = "/etc", .dest = "/etc" } },
            .{ .proc = "/proc" },
            .{ .dev = "/dev" },
            .{ .tmpfs = .{ .dest = "/tmp" } },
        } else &.{},
    };

    try libvoid.validate(config);

    const sync_pipe = try posix.pipe();
    const done_pipe = try posix.pipe();

    const pid = try posix.fork();

    if (pid == 0) {
        posix.close(sync_pipe[0]);
        posix.close(done_pipe[1]);

        const sync = libvoid.UsernsSync{
            .ready_fd = sync_pipe[1],
            .done_fd = done_pipe[0],
        };

        libvoid.applyIsolationInChildSync(config, allocator, sync) catch |err| {
            writeLog("{s} FAILED: {}\n", .{ label, err });
            posix.exit(1);
        };

        const envp = [_:null]?[*:0]const u8{null};
        const argv = [_:null]?[*:0]const u8{
            "/bin/sh",
            "-c",
            "echo uid=$(id -u) hostname=$(hostname) pid=$$; echo '---'; ls /",
            null,
        };

        const err = linux.execve("/bin/sh", &argv, &envp);
        writeLog("{s} execve failed: {}\n", .{ label, err });
        posix.exit(127);
    }

    // Parent
    posix.close(sync_pipe[1]);
    posix.close(done_pipe[0]);

    var buf: [1]u8 = undefined;
    _ = posix.read(sync_pipe[0], &buf) catch {};
    posix.close(sync_pipe[0]);

    libvoid.namespace.writeUserRootMappings(allocator, pid) catch |err| {
        std.debug.print("  writeUserRootMappings failed: {}\n", .{err});
        posix.exit(1);
    };

    _ = posix.write(done_pipe[1], &[_]u8{1}) catch {};
    posix.close(done_pipe[1]);

    const wait_result = posix.waitpid(pid, 0);
    const c = @cImport(@cInclude("sys/wait.h"));
    const status = @as(c_int, @bitCast(wait_result.status));
    const exit_code: u8 = if (c.WIFEXITED(status))
        @intCast(c.WEXITSTATUS(status))
    else if (c.WIFSIGNALED(status))
        @intCast((128 + c.WTERMSIG(status)) & 0xff)
    else
        1;

    if (exit_code == 0)
        std.debug.print("  PASS (exit=0)\n", .{})
    else
        std.debug.print("  FAIL (exit={d})\n", .{exit_code});
}

fn writeLog(comptime fmt: []const u8, args: anytype) void {
    const f = std.fs.openFileAbsolute("/tmp/libvoid-test.log", .{ .mode = .write_only }) catch
        std.fs.createFileAbsolute("/tmp/libvoid-test.log", .{}) catch return;
    defer f.close();
    f.seekFromEnd(0) catch {};
    var buf: [512]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, fmt, args) catch return;
    _ = f.write(msg) catch {};
}
