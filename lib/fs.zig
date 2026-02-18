const std = @import("std");
const linux = std.os.linux;
const FsAction = @import("config.zig").FsAction;
const fs_actions = @import("fs_actions.zig");
const mounts = @import("mounts.zig");
const checkErr = @import("utils.zig").checkErr;

rootfs: []const u8,
instance_id: []const u8,
actions: []const FsAction,

const Fs = @This();

pub fn init(rootfs: []const u8, instance_id: []const u8, actions: []const FsAction) Fs {
    return .{ .rootfs = rootfs, .instance_id = instance_id, .actions = actions };
}

pub fn setup(self: *Fs, mount_fs: bool, use_pivot_root: bool) !void {
    if (!mount_fs) {
        if (!std.mem.eql(u8, self.rootfs, "/")) {
            try mounts.enterRoot(self.rootfs, use_pivot_root);
        }
        return;
    }

    // When rootfs is "/" and we have fs_actions, use the tmpfs+pivot approach:
    // 1. Create a tmpfs as the new root
    // 2. Bind-mount only the specified dirs into it
    // 3. pivot_root to the tmpfs (old root becomes invisible)
    //
    // This is how bubblewrap achieves filesystem isolation without a pre-built rootfs.
    const is_host_root = std.mem.eql(u8, self.rootfs, "/");

    if (is_host_root) {
        try mounts.makeRootSlave();

        // Create tmpfs new root
        const newroot = try std.fmt.allocPrint(
            std.heap.page_allocator,
            "/tmp/voidbox-newroot-{s}",
            .{self.instance_id},
        );
        defer std.heap.page_allocator.free(newroot);

        {
            var root = try std.fs.openDirAbsolute("/", .{});
            defer root.close();
            try root.makePath(std.mem.trimLeft(u8, newroot, "/"));
        }
        try mountTmpfs(newroot);

        // Execute fs_actions with destinations inside the new root.
        // This is always run for host-root mode, including empty action lists,
        // to keep rootfs semantics strict and isolated.
        try fs_actions.executePrefixed(self.instance_id, self.actions, newroot);

        // pivot_root to the new root
        try mounts.pivotRoot(newroot);
        return;
    }

    try mounts.makeRootSlave();
    try mounts.enterRoot(self.rootfs, use_pivot_root);
    try mounts.makeRootPrivate();

    if (self.actions.len == 0) return;

    try fs_actions.execute(self.instance_id, self.actions);
}

fn mountTmpfs(dest: []const u8) !void {
    var dest_z = try std.posix.toPosixPath(dest);
    try checkErr(linux.mount("tmpfs", &dest_z, "tmpfs", linux.MS.NOSUID | linux.MS.NODEV, 0), error.MountTmpFs);
}

pub fn cleanupRuntimeArtifacts(self: *Fs) void {
    fs_actions.cleanupInstanceArtifacts(self.rootfs, self.instance_id);
}
