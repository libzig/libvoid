const std = @import("std");

pub const ResourceLimits = struct {
    mem: ?[]const u8 = null,
    cpu: ?[]const u8 = null,
    pids: ?[]const u8 = null,
};

pub const IsolationOptions = struct {
    user: bool = true,
    net: bool = true,
    mount: bool = true,
    pid: bool = true,
    uts: bool = true,
    ipc: bool = true,
    cgroup: bool = false,
};

pub const NamespaceFds = struct {
    user: ?i32 = null,
    user2: ?i32 = null,
    pid: ?i32 = null,
    net: ?i32 = null,
    mount: ?i32 = null,
    uts: ?i32 = null,
    ipc: ?i32 = null,
};

pub const LaunchProfile = enum {
    minimal,
    default,
    full_isolation,
};

pub const MountPair = struct {
    src: []const u8,
    dest: []const u8,
};

pub const TmpfsMount = struct {
    dest: []const u8,
    size_bytes: ?usize = null,
    mode: ?u32 = null,
};

pub const DirAction = struct {
    path: []const u8,
    mode: ?u32 = null,
};

pub const SymlinkAction = struct {
    target: []const u8,
    path: []const u8,
};

pub const ChmodAction = struct {
    path: []const u8,
    mode: u32,
};

pub const OverlaySource = struct {
    key: []const u8,
    path: []const u8,
};

pub const OverlayAction = struct {
    source_key: []const u8,
    upper: []const u8,
    work: []const u8,
    dest: []const u8,
};

pub const TmpOverlayAction = struct {
    source_key: []const u8,
    dest: []const u8,
};

pub const RoOverlayAction = struct {
    source_key: []const u8,
    dest: []const u8,
};

pub const DataBindAction = struct {
    dest: []const u8,
    data: []const u8,
};

pub const FdDataBindAction = struct {
    dest: []const u8,
    fd: i32,
};

pub const FdFileAction = struct {
    path: []const u8,
    fd: i32,
};

pub const FileAction = struct {
    path: []const u8,
    data: []const u8,
};

pub const FsAction = union(enum) {
    perms: u32,
    size: usize,
    bind: MountPair,
    bind_try: MountPair,
    dev_bind: MountPair,
    dev_bind_try: MountPair,
    ro_bind: MountPair,
    ro_bind_try: MountPair,
    proc: []const u8,
    dev: []const u8,
    mqueue: []const u8,
    tmpfs: TmpfsMount,
    dir: DirAction,
    symlink: SymlinkAction,
    chmod: ChmodAction,
    remount_ro: []const u8,
    overlay_src: OverlaySource,
    overlay: OverlayAction,
    tmp_overlay: TmpOverlayAction,
    ro_overlay: RoOverlayAction,
    bind_data: DataBindAction,
    ro_bind_data: DataBindAction,
    file: FileAction,
    bind_data_fd: FdDataBindAction,
    ro_bind_data_fd: FdDataBindAction,
    file_fd: FdFileAction,
};

pub const EnvironmentEntry = struct {
    key: []const u8,
    value: []const u8,
};

pub const ProcessOptions = struct {
    chdir: ?[]const u8 = null,
    argv0: ?[]const u8 = null,
    clear_env: bool = false,
    set_env: []const EnvironmentEntry = &.{},
    unset_env: []const []const u8 = &.{},
    inherit_fds: []const i32 = &.{},
    new_session: bool = false,
    die_with_parent: bool = false,
};

pub const RuntimeOptions = struct {
    uid: ?std.os.linux.uid_t = null,
    gid: ?std.os.linux.gid_t = null,
    hostname: ?[]const u8 = null,
    as_pid_1: bool = false,
    fail_on_runtime_warnings: bool = false,
    use_pivot_root: bool = true,
};

pub const StatusOptions = struct {
    pub const NamespaceIds = struct {
        user: ?u64 = null,
        pid: ?u64 = null,
        net: ?u64 = null,
        mount: ?u64 = null,
        uts: ?u64 = null,
        ipc: ?u64 = null,
    };

    pub const EventKind = enum {
        runtime_init_warnings,
        spawned,
        setup_finished,
        exited,
    };

    pub const Event = struct {
        kind: EventKind,
        pid: std.posix.pid_t,
        timestamp: i64,
        exit_code: ?u8 = null,
        warning_count: ?u16 = null,
        ns_ids: NamespaceIds = .{},
    };

    pub const EventCallback = *const fn (ctx: ?*anyopaque, event: Event) anyerror!void;

    json_status_fd: ?i32 = null,
    info_fd: ?i32 = null,
    sync_fd: ?i32 = null,
    block_fd: ?i32 = null,
    userns_block_fd: ?i32 = null,
    lock_file_path: ?[]const u8 = null,
    on_event: ?EventCallback = null,
    callback_ctx: ?*anyopaque = null,
};

pub const LandlockAccess = enum {
    read,
    write,
    read_write,
    execute,
};

pub const LandlockFsRule = struct {
    path: []const u8,
    access: LandlockAccess,
    try_: bool = false,
};

pub const LandlockNetAccess = enum {
    bind,
    connect,
    bind_connect,
};

pub const LandlockNetRule = struct {
    port: u16,
    access: LandlockNetAccess,
};

pub const LandlockOptions = struct {
    enabled: bool = false,
    fs_rules: []const LandlockFsRule = &.{},
    net_rules: []const LandlockNetRule = &.{},
};

pub const SecurityOptions = struct {
    pub const SeccompMode = enum {
        disabled,
        strict,
    };

    pub const SeccompInstruction = extern struct {
        code: u16,
        jt: u8,
        jf: u8,
        k: u32,
    };

    no_new_privs: bool = true,
    cap_drop: []const u8 = &.{},
    cap_add: []const u8 = &.{},
    seccomp_mode: SeccompMode = .disabled,
    seccomp_filter: ?[]const SeccompInstruction = null,
    seccomp_filters: []const []const SeccompInstruction = &.{},
    seccomp_filter_fds: []const i32 = &.{},
    disable_userns: bool = false,
    assert_userns_disabled: bool = false,
    exec_label: ?[]const u8 = null,
    file_label: ?[]const u8 = null,
    landlock: LandlockOptions = .{},
};

pub const JailConfig = struct {
    name: []const u8,
    rootfs_path: []const u8,
    cmd: []const []const u8,
    resources: ResourceLimits = .{},
    isolation: IsolationOptions = .{},
    namespace_fds: NamespaceFds = .{},
    process: ProcessOptions = .{},
    runtime: RuntimeOptions = .{},
    security: SecurityOptions = .{},
    status: StatusOptions = .{},
    fs_actions: []const FsAction = &.{},
};

pub const ShellConfig = struct {
    name: []const u8 = "shell",
    rootfs_path: []const u8,
    shell_path: []const u8 = "/bin/sh",
    shell_args: []const []const u8 = &.{},
    resources: ResourceLimits = .{},
    isolation: IsolationOptions = .{},
    namespace_fds: NamespaceFds = .{},
    process: ProcessOptions = .{},
    runtime: RuntimeOptions = .{},
    security: SecurityOptions = .{},
    status: StatusOptions = .{},
    fs_actions: []const FsAction = &.{},
};

pub const RunOutcome = struct {
    pid: std.posix.pid_t,
    exit_code: u8,
};

pub fn default_shell_config(rootfs_path: []const u8) ShellConfig {
    return .{ .rootfs_path = rootfs_path };
}
