const std = @import("std");
const log = std.log;
const linux = std.os.linux;
const checkErr = @import("utils.zig").checkErr;
const c = @cImport({
    @cInclude("signal.h");
    @cInclude("sys/wait.h");
});
const Net = @import("network.zig");
const Cgroup = @import("cgroup.zig");
const Fs = @import("fs.zig");
const namespace = @import("namespace.zig");
const namespace_sequence = @import("namespace_sequence.zig");
const process_exec = @import("process_exec.zig");
const JailConfig = @import("config.zig").JailConfig;
const IsolationOptions = @import("config.zig").IsolationOptions;
const NamespaceFds = @import("config.zig").NamespaceFds;
const ProcessOptions = @import("config.zig").ProcessOptions;
const RuntimeOptions = @import("config.zig").RuntimeOptions;
const SecurityOptions = @import("config.zig").SecurityOptions;
const StatusOptions = @import("config.zig").StatusOptions;

const ChildProcessArgs = struct {
    container: *Container,
    pipe: [2]i32,
    setup_pipe: [2]i32,
    uid: linux.uid_t,
    gid: linux.gid_t,
};

const Container = @This();
var pid1_forward_target: c.sig_atomic_t = 0;
const FORWARDED_SIGNALS = [_]c_int{ c.SIGTERM, c.SIGINT, c.SIGHUP, c.SIGQUIT, c.SIGUSR1, c.SIGUSR2 };

fn signalSetContains(signals: []const c_int, sig: c_int) bool {
    for (signals) |item| {
        if (item == sig) return true;
    }
    return false;
}
name: []const u8,
instance_id: []const u8,
cmd: []const []const u8,
isolation: IsolationOptions,
namespace_fds: NamespaceFds,
process: ProcessOptions,
runtime: RuntimeOptions,
security: SecurityOptions,
status: StatusOptions,

fs: Fs,
net: ?Net,
cgroup: Cgroup,
allocator: std.mem.Allocator,

pub fn init(run_args: JailConfig, allocator: std.mem.Allocator) !Container {
    const instance_id = try makeInstanceId(allocator, run_args.name);
    errdefer allocator.free(instance_id);

    return .{
        .name = run_args.name,
        .instance_id = instance_id,
        .fs = Fs.init(run_args.rootfs_path, instance_id, run_args.fs_actions),
        .cmd = run_args.cmd,
        .isolation = run_args.isolation,
        .namespace_fds = run_args.namespace_fds,
        .process = run_args.process,
        .runtime = run_args.runtime,
        .security = run_args.security,
        .status = run_args.status,
        .net = if (run_args.isolation.net) try Net.init(allocator, instance_id) else null,
        .allocator = allocator,
        .cgroup = try Cgroup.init(instance_id, run_args.resources, allocator),
    };
}

fn initNetwork(self: *Container) !void {
    if (self.net) |*net| {
        try net.enableNat();
        try net.setUpBridge();
        try net.createVethPair();
        try net.setupDnsResolverConfig(self.fs.rootfs);
    }
}

fn sethostname(self: *Container) !void {
    if (!self.isolation.uts and self.runtime.hostname == null) return;
    const value = self.runtime.hostname orelse self.name;
    try checkErr(linux.syscall2(.sethostname, @intFromPtr(value.ptr), value.len), error.SetHostnameFailed);
}

pub fn run(self: *Container) !linux.pid_t {
    const pid = try self.spawn();
    _ = try self.wait(pid);
    return pid;
}

pub fn spawn(self: *Container) !linux.pid_t {
    // setup network virtual interfaces and namespace
    try self.initNetwork();

    var childp_args = ChildProcessArgs{
        .container = self,
        .pipe = undefined,
        .setup_pipe = undefined,
        .uid = self.runtime.uid orelse if (self.isolation.user or self.namespace_fds.user != null) 0 else linux.getuid(),
        .gid = self.runtime.gid orelse if (self.isolation.user or self.namespace_fds.user != null) 0 else linux.getgid(),
    };
    try checkErr(linux.pipe2(&childp_args.pipe, .{ .CLOEXEC = true }), error.Pipe);
    checkErr(linux.pipe2(&childp_args.setup_pipe, .{ .CLOEXEC = true }), error.Pipe) catch |err| {
        _ = linux.close(childp_args.pipe[0]);
        _ = linux.close(childp_args.pipe[1]);
        return err;
    };
    var parent_read_open = true;
    var parent_write_open = true;
    var parent_setup_read_open = true;
    var parent_setup_write_open = true;
    errdefer {
        if (parent_read_open) _ = linux.close(childp_args.pipe[0]);
        if (parent_write_open) _ = linux.close(childp_args.pipe[1]);
        if (parent_setup_read_open) _ = linux.close(childp_args.setup_pipe[0]);
        if (parent_setup_write_open) _ = linux.close(childp_args.setup_pipe[1]);
    }

    var stack = try self.allocator.alloc(u8, 1024 * 1024);
    defer self.allocator.free(stack);
    var ctid: i32 = 0;
    var ptid: i32 = 0;
    var child_pid: ?linux.pid_t = null;
    errdefer if (child_pid) |pid| killAndReapChild(pid);

    const clone_flags = namespace.computeCloneFlags(self.isolation);
    const clone_res = linux.clone(childFn, @intFromPtr(&stack[0]) + stack.len, clone_flags, @intFromPtr(&childp_args), &ptid, 0, &ctid);
    try checkErr(clone_res, error.CloneFailed);

    const pid_signed: isize = @bitCast(clone_res);
    if (pid_signed <= 0) return error.CloneFailed;
    const pid: linux.pid_t = @intCast(pid_signed);
    child_pid = pid;
    _ = linux.close(childp_args.pipe[0]);
    parent_read_open = false;
    _ = linux.close(childp_args.setup_pipe[1]);
    parent_setup_write_open = false;

    // move one of the veth pairs to
    // the child process network namespace
    if (self.net) |*net| {
        try net.moveVethToNs(pid);
    }
    // enter container cgroup
    try self.cgroup.enterCgroup(pid);

    if (self.status.userns_block_fd) |fd| {
        try waitForFd(fd);
    }
    if (self.isolation.user) {
        namespace.writeUserRootMappings(self.allocator, pid) catch |err| {
            _ = linux.close(childp_args.pipe[1]);
            parent_write_open = false;
            _ = linux.close(childp_args.setup_pipe[0]);
            parent_setup_read_open = false;
            std.posix.kill(pid, std.posix.SIG.KILL) catch {};
            _ = std.posix.waitpid(pid, 0);
            return err;
        };
    }

    // signal done by writing to pipe
    const buff = [_]u8{0};
    const signal_n = try writeOneByte(childp_args.pipe[1], &buff);
    if (signal_n != 1) return error.SpawnFailed;
    _ = linux.close(childp_args.pipe[1]);
    parent_write_open = false;

    var ready: [1]u8 = undefined;
    const ready_n = readOneByte(childp_args.setup_pipe[0], &ready) catch {
        _ = linux.close(childp_args.setup_pipe[0]);
        parent_setup_read_open = false;
        return error.SpawnFailed;
    };
    _ = linux.close(childp_args.setup_pipe[0]);
    parent_setup_read_open = false;
    if (ready_n != 1 or ready[0] != 1) return error.SpawnFailed;

    child_pid = null;
    return @intCast(pid);
}

fn killAndReapChild(pid: linux.pid_t) void {
    std.posix.kill(pid, std.posix.SIG.KILL) catch {};
    _ = std.posix.waitpid(pid, 0);
}

pub fn wait(self: *Container, pid: linux.pid_t) !u8 {
    defer self.fs.cleanupRuntimeArtifacts();
    const wait_res = std.posix.waitpid(pid, 0);
    return decodeWaitStatus(wait_res.status);
}

// initializes the container environment
// and executes the user passed cmd
fn execCmd(self: *Container, uid: linux.uid_t, gid: linux.gid_t, setup_ready_fd: ?i32) !void {
    const old_cwd = std.process.getCwdAlloc(self.allocator) catch null;
    defer if (old_cwd) |cwd| self.allocator.free(cwd);

    try process_exec.prepare(uid, gid, self.process, self.security, self.namespace_fds);

    try self.sethostname();
    try self.fs.setup(self.isolation.mount, self.runtime.use_pivot_root);
    try applyWorkingDirectory(self.process, self.allocator, old_cwd);
    if (self.net) |*net| {
        if (self.namespace_fds.net != null) {
            // network namespace already attached; skip interface setup
        } else {
            try net.setupContainerVethIf();
        }
    }

    try process_exec.finalizeNamespaces(self.namespace_fds);
    try process_exec.enforceUserNsPolicy(self.security, self.allocator);

    if (setup_ready_fd) |fd| {
        const one = [_]u8{1};
        const n = writeOneByte(fd, &one) catch {
            _ = linux.close(fd);
            return error.SetupSyncFailed;
        };
        if (n != 1) {
            _ = linux.close(fd);
            return error.SetupSyncFailed;
        }
        _ = linux.close(fd);
    }

    try process_exec.applyLandlock(self.security);
    try process_exec.applySeccomp(self.security, self.allocator);
    try process_exec.exec(self.allocator, self.cmd, self.process);
}

fn waitForFd(fd: i32) !void {
    var buf: [1]u8 = undefined;
    const n = try readOneByte(fd, &buf);
    if (n != 1) return error.SyncFdClosed;
    if (buf[0] != 1) return error.SyncFdProtocolViolation;
}

fn readOneByte(fd: i32, out: *[1]u8) !usize {
    return std.posix.read(fd, out);
}

fn writeOneByte(fd: i32, data: *const [1]u8) !usize {
    return std.posix.write(fd, data);
}

fn applyWorkingDirectory(process: ProcessOptions, allocator: std.mem.Allocator, old_cwd: ?[]const u8) !void {
    if (process.chdir) |target| {
        std.posix.chdir(target) catch return error.ChdirFailed;
        return;
    }

    const home = std.process.getEnvVarOwned(allocator, "HOME") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => return err,
    };
    defer if (home) |path| allocator.free(path);

    const candidates = workingDirectoryCandidates(old_cwd, home);
    for (candidates) |candidate| {
        const path = candidate orelse continue;
        std.posix.chdir(path) catch continue;
        return;
    }

    return error.ChdirFailed;
}

fn workingDirectoryCandidates(old_cwd: ?[]const u8, home: ?[]const u8) [3]?[]const u8 {
    return .{ old_cwd, home, "/" };
}

export fn childFn(a: usize) u8 {
    const arg: *ChildProcessArgs = @ptrFromInt(a);
    _ = linux.close(arg.pipe[1]);
    _ = linux.close(arg.setup_pipe[0]);
    // block until parent sets up needed resources
    {
        var buff = [_]u8{0};
        const n = readOneByte(arg.pipe[0], &buff) catch {
            childExit(127);
        };
        if (n != 1 or buff[0] != 0) {
            childExit(127);
        }
    }

    if (arg.container.namespace_fds.pid) |pidns_fd| {
        namespace_sequence.preparePidNamespace(pidns_fd, arg.container.isolation.pid) catch {
            childExit(127);
        };

        const pid = std.posix.fork() catch {
            childExit(127);
        };

        if (pid != 0) {
            const wait_res = std.posix.waitpid(pid, 0);
            const code = decodeWaitStatus(wait_res.status) catch 127;
            childExit(code);
        }
    }

    if (arg.container.isolation.pid) {
        if (arg.container.runtime.as_pid_1) {
            arg.container.execCmd(arg.uid, arg.gid, arg.setup_pipe[1]) catch {
                childExit(127);
            };
            childExit(0);
        }

        const code = arg.container.execAsPid1(arg.uid, arg.gid, arg.setup_pipe[1]) catch {
            childExit(127);
        };
        childExit(code);
    }

    if (arg.container.isolation.user) {
        const code = arg.container.execAsPid1(arg.uid, arg.gid, arg.setup_pipe[1]) catch {
            childExit(127);
        };
        childExit(code);
    }

    arg.container.execCmd(arg.uid, arg.gid, arg.setup_pipe[1]) catch {
        childExit(127);
    };

    return 0;
}

fn execAsPid1(self: *Container, uid: linux.uid_t, gid: linux.gid_t, setup_ready_fd: ?i32) !u8 {
    const child_pid = try std.posix.fork();
    if (child_pid == 0) {
        self.execCmd(uid, gid, setup_ready_fd) catch {
            childExit(127);
        };
        childExit(0);
    }

    std.posix.setpgid(child_pid, child_pid) catch {};
    try installPid1SignalForwarding(child_pid);
    defer resetPid1SignalForwarding();

    const code = try waitMainChildAsPid1(child_pid);
    reapChildrenNonBlocking();
    return code;
}

fn installPid1SignalForwarding(child_pid: linux.pid_t) !void {
    pid1_forward_target = @intCast(child_pid);
    errdefer resetPid1SignalForwarding();

    for (FORWARDED_SIGNALS) |sig| {
        if (c.signal(sig, pid1ForwardSignalHandler) == c.SIG_ERR) {
            return error.SignalInstallFailed;
        }
    }
}

fn resetPid1SignalForwarding() void {
    for (FORWARDED_SIGNALS) |sig| {
        _ = c.signal(sig, c.SIG_DFL);
    }
    pid1_forward_target = 0;
}

fn pid1ForwardSignalHandler(sig: c_int) callconv(.c) void {
    const target: linux.pid_t = @intCast(pid1_forward_target);
    if (target <= 0) return;
    if (c.kill(-target, sig) == -1) {
        _ = c.kill(target, sig);
    }
}

fn waitMainChildAsPid1(main_child_pid: linux.pid_t) !u8 {
    while (true) {
        const wait_res = std.posix.waitpid(-1, 0);
        if (wait_res.pid == main_child_pid) {
            return decodeWaitStatus(wait_res.status);
        }
    }
}

fn reapChildrenNonBlocking() void {
    while (true) {
        const res = std.posix.waitpid(-1, std.posix.W.NOHANG);
        if (res.pid <= 0) break;
    }
}

fn childExit(code: u8) noreturn {
    linux.exit(code);
}

fn decodeWaitStatus(status_bits: u32) !u8 {
    const status = @as(c_int, @bitCast(status_bits));
    if (c.WIFEXITED(status)) {
        return @intCast(c.WEXITSTATUS(status));
    }
    if (c.WIFSIGNALED(status)) {
        const sig = c.WTERMSIG(status);
        return @intCast((128 + sig) & 0xff);
    }
    return error.WaitFailed;
}

pub fn deinit(self: *Container) void {
    self.cgroup.deinit() catch |e| {
        log.err("cgroup deinit failed: {}", .{e});
    };
    if (self.net) |*net| {
        net.deinit() catch log.err("net deinit failed", .{});
    }
    self.allocator.free(self.instance_id);
}

pub fn makeInstanceId(allocator: std.mem.Allocator, name: []const u8) ![]const u8 {
    const now_i128 = std.time.nanoTimestamp();
    const now: u64 = @truncate(@as(u128, @bitCast(now_i128)));
    const pid: u64 = @intCast(linux.getpid());
    const hashed = std.hash.Wyhash.hash(0, name);
    const token: u32 = @truncate(hashed ^ now ^ (pid << 32));
    return std.fmt.allocPrint(allocator, "{x:0>8}", .{token});
}

test "forwarded signal set includes common termination signals" {
    var has_term = false;
    var has_int = false;
    var has_hup = false;
    var has_quit = false;
    for (FORWARDED_SIGNALS) |sig| {
        if (sig == c.SIGTERM) has_term = true;
        if (sig == c.SIGINT) has_int = true;
        if (sig == c.SIGHUP) has_hup = true;
        if (sig == c.SIGQUIT) has_quit = true;
    }
    try std.testing.expect(has_term);
    try std.testing.expect(has_int);
    try std.testing.expect(has_hup);
    try std.testing.expect(has_quit);
}

test "forwarded signal set excludes SIGCHLD and uncatchable signals" {
    try std.testing.expect(!signalSetContains(&FORWARDED_SIGNALS, c.SIGCHLD));
    try std.testing.expect(!signalSetContains(&FORWARDED_SIGNALS, c.SIGKILL));
    try std.testing.expect(!signalSetContains(&FORWARDED_SIGNALS, c.SIGSTOP));
}

test "waitForFd consumes synchronization byte" {
    const pipefds = try std.posix.pipe();
    defer std.posix.close(pipefds[0]);
    defer std.posix.close(pipefds[1]);

    const one = [_]u8{1};
    _ = try std.posix.write(pipefds[1], &one);
    try waitForFd(pipefds[0]);
}

test "waitForFd errors when synchronization writer is closed" {
    const pipefds = try std.posix.pipe();
    defer std.posix.close(pipefds[0]);
    std.posix.close(pipefds[1]);

    try std.testing.expectError(error.SyncFdClosed, waitForFd(pipefds[0]));
}

test "waitForFd rejects unexpected synchronization byte" {
    const pipefds = try std.posix.pipe();
    defer std.posix.close(pipefds[0]);
    defer std.posix.close(pipefds[1]);

    const zero = [_]u8{0};
    _ = try std.posix.write(pipefds[1], &zero);
    try std.testing.expectError(error.SyncFdProtocolViolation, waitForFd(pipefds[0]));
}

test "killAndReapChild terminates child process" {
    const pid = try std.posix.fork();
    if (pid == 0) {
        _ = linux.syscall0(.pause);
        childExit(0);
    }

    killAndReapChild(pid);
    try std.testing.expectError(error.ProcessNotFound, std.posix.kill(pid, 0));
}

test "workingDirectoryCandidates prioritizes old cwd then home then root" {
    const candidates = workingDirectoryCandidates("/old", "/home/test");
    try std.testing.expectEqualStrings("/old", candidates[0].?);
    try std.testing.expectEqualStrings("/home/test", candidates[1].?);
    try std.testing.expectEqualStrings("/", candidates[2].?);
}

test "workingDirectoryCandidates keeps root fallback when inputs missing" {
    const candidates = workingDirectoryCandidates(null, null);
    try std.testing.expect(candidates[0] == null);
    try std.testing.expect(candidates[1] == null);
    try std.testing.expectEqualStrings("/", candidates[2].?);
}
