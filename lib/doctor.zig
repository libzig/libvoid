const std = @import("std");
const landlock = @import("landlock.zig");

pub const KernelVersion = struct {
    major: u32,
    minor: u32,
    patch: u32,
};

pub const CapabilityMatrix = struct {
    overlayfs: bool,
    seccomp_filter: bool,
    namespace_attach: bool,
    userns_mapping: bool,
    procfs: bool,
    tmpfs: bool,
    devtmpfs: bool,
};

pub const DoctorReport = struct {
    is_linux: bool,
    kernel_version: ?KernelVersion,
    has_user_ns: bool,
    has_mount_ns: bool,
    has_pid_ns: bool,
    has_net_ns: bool,
    has_uts_ns: bool,
    has_ipc_ns: bool,
    cgroup_v2_available: bool,
    iptables_available: bool,
    nft_available: bool,
    unpriv_userns_clone_enabled: ?bool,
    capabilities: CapabilityMatrix,
    landlock_available: bool,
    landlock_abi_version: ?u32,
    readiness_score: u8,
    full_isolation_ready: bool,

    pub fn strictReady(self: DoctorReport) bool {
        return self.full_isolation_ready;
    }

    pub fn print(self: DoctorReport, writer: anytype) !void {
        try writer.print("voidbox doctor\n", .{});
        try writer.print("- linux: {}\n", .{self.is_linux});
        if (self.kernel_version) |v| {
            try writer.print("- kernel: {}.{}.{}\n", .{ v.major, v.minor, v.patch });
        } else {
            try writer.print("- kernel: unknown\n", .{});
        }
        try writer.print("- namespaces: user={} mount={} pid={} net={} uts={} ipc={}\n", .{ self.has_user_ns, self.has_mount_ns, self.has_pid_ns, self.has_net_ns, self.has_uts_ns, self.has_ipc_ns });
        try writer.print("- cgroup v2: {}\n", .{self.cgroup_v2_available});
        try writer.print("- net tools: iptables={} nft={}\n", .{ self.iptables_available, self.nft_available });
        if (self.unpriv_userns_clone_enabled) |enabled| {
            try writer.print("- kernel.unprivileged_userns_clone: {}\n", .{enabled});
        } else {
            try writer.print("- kernel.unprivileged_userns_clone: unknown\n", .{});
        }
        try writer.print("- capability matrix: overlayfs={} seccomp_filter={} namespace_attach={} userns_mapping={} procfs={} tmpfs={} devtmpfs={}\n", .{
            self.capabilities.overlayfs,
            self.capabilities.seccomp_filter,
            self.capabilities.namespace_attach,
            self.capabilities.userns_mapping,
            self.capabilities.procfs,
            self.capabilities.tmpfs,
            self.capabilities.devtmpfs,
        });
        if (self.landlock_abi_version) |v| {
            try writer.print("- landlock: abi v{}\n", .{v});
        } else {
            try writer.print("- landlock: unavailable\n", .{});
        }
        try writer.print("- readiness score: {}/100\n", .{self.readiness_score});
        try writer.print("- full isolation ready: {}\n", .{self.full_isolation_ready});

        if (!self.cgroup_v2_available) {
            try writer.print("  recommendation: enable cgroup v2 for resource controls\n", .{});
        }
        if (!self.capabilities.seccomp_filter) {
            try writer.print("  recommendation: kernel seccomp filter support missing\n", .{});
        }
        if (!self.capabilities.overlayfs) {
            try writer.print("  recommendation: overlayfs unavailable; overlay actions disabled\n", .{});
        }
        if (!self.iptables_available and !self.nft_available) {
            try writer.print("  recommendation: install iptables or nft for bridge NAT\n", .{});
        }
        if (!self.landlock_available) {
            try writer.print("  recommendation: upgrade to kernel 5.13+ for Landlock path restrictions\n", .{});
        }
    }

    pub fn printJson(self: DoctorReport, writer: anytype) !void {
        try writer.print("{{\"is_linux\":{}", .{self.is_linux});
        if (self.kernel_version) |v| {
            try writer.print(",\"kernel_version\":{{\"major\":{},\"minor\":{},\"patch\":{}}}", .{ v.major, v.minor, v.patch });
        } else {
            try writer.print(",\"kernel_version\":null", .{});
        }
        try writer.print(",\"namespaces\":{{\"user\":{},\"mount\":{},\"pid\":{},\"net\":{},\"uts\":{},\"ipc\":{}}}", .{ self.has_user_ns, self.has_mount_ns, self.has_pid_ns, self.has_net_ns, self.has_uts_ns, self.has_ipc_ns });
        try writer.print(",\"cgroup_v2_available\":{}", .{self.cgroup_v2_available});
        try writer.print(",\"net_tools\":{{\"iptables\":{},\"nft\":{}}}", .{ self.iptables_available, self.nft_available });
        if (self.unpriv_userns_clone_enabled) |enabled| {
            try writer.print(",\"unpriv_userns_clone_enabled\":{}", .{enabled});
        } else {
            try writer.print(",\"unpriv_userns_clone_enabled\":null", .{});
        }
        try writer.print(",\"capabilities\":{{\"overlayfs\":{},\"seccomp_filter\":{},\"namespace_attach\":{},\"userns_mapping\":{},\"procfs\":{},\"tmpfs\":{},\"devtmpfs\":{}}}", .{
            self.capabilities.overlayfs,
            self.capabilities.seccomp_filter,
            self.capabilities.namespace_attach,
            self.capabilities.userns_mapping,
            self.capabilities.procfs,
            self.capabilities.tmpfs,
            self.capabilities.devtmpfs,
        });
        try writer.print(",\"landlock_available\":{}", .{self.landlock_available});
        if (self.landlock_abi_version) |v| {
            try writer.print(",\"landlock_abi_version\":{}", .{v});
        } else {
            try writer.print(",\"landlock_abi_version\":null", .{});
        }
        try writer.print(",\"readiness_score\":{}", .{self.readiness_score});
        try writer.print(",\"full_isolation_ready\":{}", .{self.full_isolation_ready});
        try writer.print(",\"strict_ready\":{}", .{self.strictReady()});
        try writer.print("}}\n", .{});
    }
};

pub fn check(allocator: std.mem.Allocator) !DoctorReport {
    const cgroup_v2 = file_exists("/sys/fs/cgroup/cgroup.controllers");
    const filesystems = try readSmallFile(allocator, "/proc/filesystems", 16 * 1024);
    defer if (filesystems) |v| allocator.free(v);

    const overlayfs = if (filesystems) |v| containsToken(v, "overlay") else false;
    const procfs = if (filesystems) |v| containsToken(v, "proc") else false;
    const tmpfs = if (filesystems) |v| containsToken(v, "tmpfs") else false;
    const devtmpfs = if (filesystems) |v| containsToken(v, "devtmpfs") else false;

    const has_user = ns_exists("/proc/self/ns/user");
    const has_mount = ns_exists("/proc/self/ns/mnt");
    const has_pid = ns_exists("/proc/self/ns/pid");
    const has_net = ns_exists("/proc/self/ns/net");
    const has_uts = ns_exists("/proc/self/ns/uts");
    const has_ipc = ns_exists("/proc/self/ns/ipc");
    const has_seccomp_filter = file_exists("/proc/sys/kernel/seccomp/actions_avail");
    const has_iptables = command_exists("iptables");
    const has_nft = command_exists("nft");

    const ll_abi = landlock.probeAbi();
    const ll_available = ll_abi != null;

    const full_isolation_ready = has_user and has_mount and has_pid and has_net and has_uts and has_ipc and cgroup_v2 and has_seccomp_filter and tmpfs and procfs;
    const readiness = computeReadinessScore(.{
        .is_linux = true,
        .has_user_ns = has_user,
        .has_mount_ns = has_mount,
        .has_pid_ns = has_pid,
        .has_net_ns = has_net,
        .has_uts_ns = has_uts,
        .has_ipc_ns = has_ipc,
        .cgroup_v2_available = cgroup_v2,
        .iptables_available = has_iptables,
        .nft_available = has_nft,
        .capabilities = .{
            .overlayfs = overlayfs,
            .seccomp_filter = has_seccomp_filter,
            .namespace_attach = has_mount and has_net,
            .userns_mapping = file_exists("/proc/self/uid_map") and file_exists("/proc/self/gid_map"),
            .procfs = procfs,
            .tmpfs = tmpfs,
            .devtmpfs = devtmpfs,
        },
    });

    return .{
        .is_linux = true,
        .kernel_version = try readKernelVersion(allocator),
        .has_user_ns = has_user,
        .has_mount_ns = has_mount,
        .has_pid_ns = has_pid,
        .has_net_ns = has_net,
        .has_uts_ns = has_uts,
        .has_ipc_ns = has_ipc,
        .cgroup_v2_available = cgroup_v2,
        .iptables_available = has_iptables,
        .nft_available = has_nft,
        .unpriv_userns_clone_enabled = read_unpriv_userns_clone(),
        .capabilities = .{
            .overlayfs = overlayfs,
            .seccomp_filter = has_seccomp_filter,
            .namespace_attach = has_mount and has_net,
            .userns_mapping = file_exists("/proc/self/uid_map") and file_exists("/proc/self/gid_map"),
            .procfs = procfs,
            .tmpfs = tmpfs,
            .devtmpfs = devtmpfs,
        },
        .landlock_available = ll_available,
        .landlock_abi_version = ll_abi,
        .readiness_score = readiness,
        .full_isolation_ready = full_isolation_ready,
    };
}

fn computeReadinessScore(report: struct {
    is_linux: bool,
    has_user_ns: bool,
    has_mount_ns: bool,
    has_pid_ns: bool,
    has_net_ns: bool,
    has_uts_ns: bool,
    has_ipc_ns: bool,
    cgroup_v2_available: bool,
    iptables_available: bool,
    nft_available: bool,
    capabilities: CapabilityMatrix,
}) u8 {
    var score: u8 = 0;
    if (report.is_linux) score += 10;
    if (report.has_user_ns) score += 10;
    if (report.has_mount_ns) score += 10;
    if (report.has_pid_ns) score += 5;
    if (report.has_net_ns) score += 5;
    if (report.has_uts_ns) score += 5;
    if (report.has_ipc_ns) score += 5;
    if (report.cgroup_v2_available) score += 10;
    if (report.capabilities.seccomp_filter) score += 10;
    if (report.capabilities.overlayfs) score += 10;
    if (report.capabilities.procfs) score += 5;
    if (report.capabilities.tmpfs) score += 5;
    if (report.capabilities.devtmpfs) score += 5;
    if (report.iptables_available or report.nft_available) score += 5;
    return score;
}

fn ns_exists(path: []const u8) bool {
    return file_exists(path);
}

fn file_exists(path: []const u8) bool {
    const file = std.fs.openFileAbsolute(path, .{}) catch return false;
    file.close();
    return true;
}

fn command_exists(cmd: []const u8) bool {
    var child = std.process.Child.init(&.{ cmd, "--version" }, std.heap.page_allocator);
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;
    const term = child.spawnAndWait() catch return false;
    return term.Exited == 0;
}

fn read_unpriv_userns_clone() ?bool {
    const path = "/proc/sys/kernel/unprivileged_userns_clone";
    const file = std.fs.openFileAbsolute(path, .{}) catch return null;
    defer file.close();

    const content = file.readToEndAlloc(std.heap.page_allocator, 64) catch return null;
    defer std.heap.page_allocator.free(content);

    const trimmed = std.mem.trim(u8, content, " \n\t\r");
    if (std.mem.eql(u8, trimmed, "0")) return false;
    if (std.mem.eql(u8, trimmed, "1")) return true;
    return null;
}

fn readKernelVersion(allocator: std.mem.Allocator) !?KernelVersion {
    const content = try readSmallFile(allocator, "/proc/sys/kernel/osrelease", 128);
    defer if (content) |v| allocator.free(v);
    if (content == null) return null;

    const trimmed = std.mem.trim(u8, content.?, " \n\t\r");
    var it = std.mem.splitScalar(u8, trimmed, '.');
    const major_s = it.next() orelse return null;
    const minor_s = it.next() orelse return null;
    const patch_part = it.next() orelse return null;

    const patch_s = patchDigits(patch_part);
    if (patch_s.len == 0) return null;

    return .{
        .major = std.fmt.parseInt(u32, major_s, 10) catch return null,
        .minor = std.fmt.parseInt(u32, minor_s, 10) catch return null,
        .patch = std.fmt.parseInt(u32, patch_s, 10) catch return null,
    };
}

fn patchDigits(input: []const u8) []const u8 {
    var end: usize = 0;
    while (end < input.len and std.ascii.isDigit(input[end])) : (end += 1) {}
    return input[0..end];
}

fn readSmallFile(allocator: std.mem.Allocator, path: []const u8, limit: usize) !?[]u8 {
    const file = std.fs.openFileAbsolute(path, .{}) catch return null;
    defer file.close();
    return file.readToEndAlloc(allocator, limit) catch return null;
}

fn containsToken(content: []const u8, token: []const u8) bool {
    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        if (std.mem.indexOf(u8, line, token) != null) return true;
    }
    return false;
}
