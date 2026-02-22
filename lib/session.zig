const std = @import("std");
const Container = @import("container.zig");
const config = @import("config.zig");
const namespace = @import("namespace.zig");
const runtime = @import("runtime.zig");
const status = @import("status.zig");

pub const JailConfig = config.JailConfig;
pub const ShellConfig = config.ShellConfig;
pub const StatusOptions = config.StatusOptions;
pub const RunOutcome = config.RunOutcome;

pub const Session = struct {
    container: Container,
    pid: std.posix.pid_t,
    status: StatusOptions,
    runtime_init: runtime.InitResult,
    lock_file: ?std.fs.File = null,
    waited: bool = false,

    pub fn runtimeWarnings(self: Session) runtime.InitResult {
        return self.runtime_init;
    }

    pub fn deinit(self: *Session) void {
        if (self.lock_file) |f| {
            f.close();
        }
        self.container.deinit();
    }
};

pub fn spawn(jail_config: JailConfig, allocator: std.mem.Allocator) !Session {
    if (jail_config.status.block_fd) |fd| {
        try waitForFd(fd);
    }

    const lock_file = if (jail_config.status.lock_file_path) |path|
        try openOrCreateAndLockFile(path)
    else
        null;
    errdefer if (lock_file) |f| f.close();

    const runtime_init = runtime.init();
    if (runtime_init.warning_count() > 0) {
        try status.emitRuntimeInitWarningsWithOptions(jail_config.status, runtime_init.warning_count());
        std.log.warn("runtime init completed with {} warning(s)", .{runtime_init.warning_count()});
        if (jail_config.runtime.fail_on_runtime_warnings) {
            return error.RuntimeInitWarning;
        }
    }
    var container = try Container.init(jail_config, allocator);
    const pid = try container.spawn();

    const ns_ids = status.queryNamespaceIds(pid) catch status.NamespaceIds{};
    try status.emitSpawnedWithOptions(jail_config.status, pid, ns_ids);
    try status.emitSetupFinishedWithOptions(jail_config.status, pid, ns_ids);
    if (jail_config.status.sync_fd) |fd| {
        try signalFd(fd);
    }

    return .{
        .container = container,
        .pid = pid,
        .status = jail_config.status,
        .runtime_init = runtime_init,
        .lock_file = lock_file,
    };
}

test "runtime warning policy can fail fast" {
    var result = runtime.InitResult{};
    result.warnings.insert(.RuntimeDirUnavailable);

    const cfg: JailConfig = .{
        .name = "test",
        .rootfs_path = "/",
        .cmd = &.{"/bin/sh"},
        .runtime = .{ .fail_on_runtime_warnings = true },
    };

    try std.testing.expect(cfg.runtime.fail_on_runtime_warnings);
    try std.testing.expect(result.warning_count() == 1);
}

pub fn wait(session: *Session) !RunOutcome {
    if (session.waited) return error.SessionAlreadyWaited;

    const exit_code = try session.container.wait(session.pid);
    session.waited = true;
    try status.emitExitedWithOptions(session.status, session.pid, exit_code);
    return .{ .pid = session.pid, .exit_code = exit_code };
}

fn waitForFd(fd: i32) !void {
    var buf: [1]u8 = undefined;
    const n = try readOneByte(fd, &buf);
    if (n != 1) return error.SyncFdClosed;
    if (buf[0] != 1) return error.SyncFdProtocolViolation;
}

fn signalFd(fd: i32) !void {
    const buf = [_]u8{1};
    const n = try writeOneByte(fd, &buf);
    if (n != 1) return error.SyncFdWriteShort;
}

fn readOneByte(fd: i32, out: *[1]u8) !usize {
    return std.posix.read(fd, out);
}

fn writeOneByte(fd: i32, data: *const [1]u8) !usize {
    return std.posix.write(fd, data);
}

fn openOrCreateAndLockFile(path: []const u8) !std.fs.File {
    var file = std.fs.openFileAbsolute(path, .{ .mode = .read_only }) catch |err| switch (err) {
        error.FileNotFound => try std.fs.createFileAbsolute(path, .{ .read = true, .truncate = false }),
        else => return err,
    };

    std.posix.flock(file.handle, std.posix.LOCK.EX | std.posix.LOCK.NB) catch |err| {
        file.close();
        return err;
    };

    return file;
}

fn lockPathForTest(allocator: std.mem.Allocator) ![]u8 {
    return std.fmt.allocPrint(allocator, "/tmp/libvoid-session-lock-test-{}", .{std.time.nanoTimestamp()});
}

test "signalFd writes supervisor sync byte" {
    const pipefds = try std.posix.pipe();
    defer std.posix.close(pipefds[0]);
    defer std.posix.close(pipefds[1]);

    try signalFd(pipefds[1]);

    var byte: [1]u8 = undefined;
    _ = try std.posix.read(pipefds[0], &byte);
    try std.testing.expectEqual(@as(u8, 1), byte[0]);
}

test "waitForFd consumes supervisor unblock byte" {
    const pipefds = try std.posix.pipe();
    defer std.posix.close(pipefds[0]);
    defer std.posix.close(pipefds[1]);

    const one = [_]u8{1};
    _ = try std.posix.write(pipefds[1], &one);
    try waitForFd(pipefds[0]);
}

test "waitForFd rejects unexpected sync byte" {
    const pipefds = try std.posix.pipe();
    defer std.posix.close(pipefds[0]);
    defer std.posix.close(pipefds[1]);

    const zero = [_]u8{0};
    _ = try std.posix.write(pipefds[1], &zero);
    try std.testing.expectError(error.SyncFdProtocolViolation, waitForFd(pipefds[0]));
}

test "waitForFd errors on closed writer" {
    const pipefds = try std.posix.pipe();
    defer std.posix.close(pipefds[0]);
    std.posix.close(pipefds[1]);

    try std.testing.expectError(error.SyncFdClosed, waitForFd(pipefds[0]));
}

test "openOrCreateAndLockFile acquires exclusive lock" {
    const tmp_path = try lockPathForTest(std.testing.allocator);
    defer std.testing.allocator.free(tmp_path);
    defer std.fs.deleteFileAbsolute(tmp_path) catch {};

    var file_a = try openOrCreateAndLockFile(tmp_path);
    defer file_a.close();

    try std.testing.expectError(error.WouldBlock, openOrCreateAndLockFile(tmp_path));
}

test "openOrCreateAndLockFile can reacquire lock after close" {
    const tmp_path = try lockPathForTest(std.testing.allocator);
    defer std.testing.allocator.free(tmp_path);
    defer std.fs.deleteFileAbsolute(tmp_path) catch {};

    {
        var first = try openOrCreateAndLockFile(tmp_path);
        first.close();
    }

    var second = try openOrCreateAndLockFile(tmp_path);
    second.close();
}
