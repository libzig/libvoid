const std = @import("std");
const linux = std.os.linux;
const checkErrAllowBusy = @import("utils.zig").checkErrAllowBusy;
const FsAction = @import("config.zig").FsAction;
const OverlaySource = @import("config.zig").OverlaySource;
const TmpfsMount = @import("config.zig").TmpfsMount;

const BIND_FLAGS: u32 = linux.MS.BIND | linux.MS.REC;
const BIND_HARDEN_FLAGS: u32 = linux.MS.BIND | linux.MS.REMOUNT | linux.MS.REC | linux.MS.NOSUID | linux.MS.NODEV;
const BIND_HARDEN_DEV_FLAGS: u32 = linux.MS.BIND | linux.MS.REMOUNT | linux.MS.REC | linux.MS.NOSUID;
const PROC_FLAGS: u32 = linux.MS.NOSUID | linux.MS.NODEV | linux.MS.NOEXEC;
const TMPFS_FLAGS: u32 = linux.MS.NOSUID | linux.MS.NODEV;
const TMP_OVERLAY_BASE: []const u8 = "/tmp/.libvoid-tmp-overlay";

const MountedTarget = struct {
    path: []const u8,
};

/// Execute fs_actions with all destination paths prefixed by `root_prefix`.
/// Used for the tmpfs+pivot approach: bind-mounts go into the new root dir
/// before pivot_root makes it the actual root.
pub fn executePrefixed(instance_id: []const u8, actions: []const FsAction, root_prefix: []const u8) !void {
    const alloc = std.heap.page_allocator;
    var overlay_sources = std.ArrayList(OverlaySource).empty;
    defer overlay_sources.deinit(alloc);
    var tmp_overlay_counter: usize = 0;
    var data_bind_counter: usize = 0;
    var current_mode: ?u32 = null;
    var current_size: ?usize = null;
    var tmp_overlay_base_ready = false;

    for (actions) |action| {
        switch (action) {
            .perms => |mode| {
                current_mode = mode;
            },
            .size => |size_bytes| {
                current_size = size_bytes;
            },
            .bind => |mp| {
                const dest = try prefixedPath(alloc, root_prefix, mp.dest);
                defer alloc.free(dest);
                try ensurePath(dest);
                try mountPath(mp.src, dest, null, BIND_FLAGS, null, error.BindMount);
                try hardenBindMount(dest, false, false);
            },
            .bind_try => |mp| {
                if (!sourceExists(mp.src)) continue;
                const dest = try prefixedPath(alloc, root_prefix, mp.dest);
                defer alloc.free(dest);
                try ensurePath(dest);
                try mountPath(mp.src, dest, null, BIND_FLAGS, null, error.BindMount);
                try hardenBindMount(dest, false, false);
            },
            .ro_bind => |mp| {
                const dest = try prefixedPath(alloc, root_prefix, mp.dest);
                defer alloc.free(dest);
                try ensurePath(dest);
                try mountPath(mp.src, dest, null, BIND_FLAGS, null, error.BindMount);
                try hardenBindMount(dest, true, false);
            },
            .ro_bind_try => |mp| {
                if (!sourceExists(mp.src)) continue;
                const dest = try prefixedPath(alloc, root_prefix, mp.dest);
                defer alloc.free(dest);
                try ensurePath(dest);
                try mountPath(mp.src, dest, null, BIND_FLAGS, null, error.BindMount);
                try hardenBindMount(dest, true, false);
            },
            .dev_bind => |mp| {
                const dest = try prefixedPath(alloc, root_prefix, mp.dest);
                defer alloc.free(dest);
                try ensurePath(dest);
                try mountPath(mp.src, dest, null, BIND_FLAGS, null, error.BindMount);
                try hardenBindMount(dest, false, true);
            },
            .dev_bind_try => |mp| {
                if (!sourceExists(mp.src)) continue;
                const dest = try prefixedPath(alloc, root_prefix, mp.dest);
                defer alloc.free(dest);
                try ensurePath(dest);
                try mountPath(mp.src, dest, null, BIND_FLAGS, null, error.BindMount);
                try hardenBindMount(dest, false, true);
            },
            .proc => |dest| {
                const full = try prefixedPath(alloc, root_prefix, dest);
                defer alloc.free(full);
                try ensurePath(full);
                try mountPath("proc", full, "proc", PROC_FLAGS, null, error.MountProc);
            },
            .dev => |dest| {
                const full = try prefixedPath(alloc, root_prefix, dest);
                defer alloc.free(full);
                try setupMinimalDevFs(full);
            },
            .tmpfs => |tmpfs| {
                const full = try prefixedPath(alloc, root_prefix, tmpfs.dest);
                defer alloc.free(full);
                try ensurePath(full);

                const eff_tmpfs = effectiveTmpfs(tmpfs, current_size, current_mode);
                if (tmpfs.size_bytes == null and eff_tmpfs.size_bytes != null) {
                    current_size = null;
                }
                if (tmpfs.mode == null and eff_tmpfs.mode != null) {
                    current_mode = null;
                }

                var opts_buf: [64]u8 = undefined;
                const opts = if (eff_tmpfs.size_bytes != null or eff_tmpfs.mode != null)
                    try formatTmpfsOpts(&opts_buf, eff_tmpfs)
                else
                    null;
                try mountPath("tmpfs", full, "tmpfs", TMPFS_FLAGS, opts, error.MountTmpFs);
            },
            .dir => |dir_action| {
                const full = try prefixedPath(alloc, root_prefix, dir_action.path);
                defer alloc.free(full);
                try ensurePath(full);
                const mode = dir_action.mode orelse takeMode(&current_mode);
                if (mode) |m| {
                    try std.posix.fchmodat(std.posix.AT.FDCWD, full, @intCast(m), 0);
                }
            },
            .symlink => |symlink| {
                const full = try prefixedPath(alloc, root_prefix, symlink.path);
                defer alloc.free(full);
                const parent = std.fs.path.dirname(full);
                if (parent) |p| try ensurePath(p);
                std.fs.cwd().symLink(symlink.target, trimPath(full), .{}) catch |err| switch (err) {
                    error.PathAlreadyExists => {},
                    else => return err,
                };
            },
            .chmod => |chmod_action| {
                const full = try prefixedPath(alloc, root_prefix, chmod_action.path);
                defer alloc.free(full);
                try std.posix.fchmodat(std.posix.AT.FDCWD, full, @intCast(chmod_action.mode), 0);
            },
            .remount_ro => |dest| {
                const full = try prefixedPath(alloc, root_prefix, dest);
                defer alloc.free(full);
                const flags = linux.MS.REMOUNT | linux.MS.RDONLY | linux.MS.NOSUID | linux.MS.NODEV;
                try mountPath(null, full, null, flags, null, error.RemountReadOnly);
            },
            .mqueue => |dest| {
                const full = try prefixedPath(alloc, root_prefix, dest);
                defer alloc.free(full);
                try ensurePath(full);
                try mountPath("mqueue", full, "mqueue", 0, null, error.MountMqueue);
            },
            .overlay_src => |src| {
                try overlay_sources.append(alloc, src);
            },
            .overlay => |o| {
                const lower = findOverlaySource(overlay_sources.items, o.source_key) orelse return error.MissingOverlaySource;

                const dest = try prefixedPath(alloc, root_prefix, o.dest);
                defer alloc.free(dest);
                const upper = try prefixedPath(alloc, root_prefix, o.upper);
                defer alloc.free(upper);
                const work = try prefixedPath(alloc, root_prefix, o.work);
                defer alloc.free(work);

                try ensurePath(dest);
                try ensurePath(upper);
                try ensurePath(work);

                var opts_buf: [std.posix.PATH_MAX - 1]u8 = undefined;
                const opts = try std.fmt.bufPrint(&opts_buf, "lowerdir={s},upperdir={s},workdir={s}", .{ lower, upper, work });
                try mountPath("overlay", dest, "overlay", 0, opts, error.MountOverlay);
            },
            .tmp_overlay => |o| {
                const lower = findOverlaySource(overlay_sources.items, o.source_key) orelse return error.MissingOverlaySource;

                const dest = try prefixedPath(alloc, root_prefix, o.dest);
                defer alloc.free(dest);
                try ensurePath(dest);

                const tmp_overlay_root = try prefixedPath(alloc, root_prefix, TMP_OVERLAY_BASE);
                defer alloc.free(tmp_overlay_root);
                if (!tmp_overlay_base_ready) {
                    try ensurePath(tmp_overlay_root);
                    try mountPath("tmpfs", tmp_overlay_root, "tmpfs", TMPFS_FLAGS, null, error.MountTmpFs);
                    tmp_overlay_base_ready = true;
                }

                const rel_overlay_base = try std.fmt.allocPrint(alloc, "{s}/{s}/{s}-{d}", .{ TMP_OVERLAY_BASE, instance_id, o.source_key, tmp_overlay_counter });
                defer alloc.free(rel_overlay_base);
                const overlay_base = try prefixedPath(alloc, root_prefix, rel_overlay_base);
                defer alloc.free(overlay_base);
                const upper = try std.fmt.allocPrint(alloc, "{s}/upper", .{overlay_base});
                defer alloc.free(upper);
                const work = try std.fmt.allocPrint(alloc, "{s}/work", .{overlay_base});
                defer alloc.free(work);

                try ensurePath(upper);
                try ensurePath(work);

                var opts_buf: [std.posix.PATH_MAX - 1]u8 = undefined;
                const opts = try std.fmt.bufPrint(&opts_buf, "lowerdir={s},upperdir={s},workdir={s}", .{ lower, upper, work });
                try mountPath("overlay", dest, "overlay", 0, opts, error.MountOverlay);
                tmp_overlay_counter += 1;
            },
            .ro_overlay => |o| {
                const lower = findOverlaySource(overlay_sources.items, o.source_key) orelse return error.MissingOverlaySource;

                const dest = try prefixedPath(alloc, root_prefix, o.dest);
                defer alloc.free(dest);
                try ensurePath(dest);

                var opts_buf: [std.posix.PATH_MAX - 1]u8 = undefined;
                const opts = try std.fmt.bufPrint(&opts_buf, "lowerdir={s}", .{lower});
                try mountPath("overlay", dest, "overlay", linux.MS.RDONLY, opts, error.MountOverlay);
            },
            .bind_data => |b| {
                const src = try writeDataSource(instance_id, b.data, data_bind_counter);
                defer alloc.free(src);

                const dest = try prefixedPath(alloc, root_prefix, b.dest);
                defer alloc.free(dest);
                try ensurePath(dest);
                try mountPath(src, dest, null, BIND_FLAGS, null, error.BindMount);
                try hardenBindMount(dest, false, false);
                std.fs.deleteFileAbsolute(src) catch {};
                data_bind_counter += 1;
            },
            .ro_bind_data => |b| {
                const src = try writeDataSource(instance_id, b.data, data_bind_counter);
                defer alloc.free(src);

                const dest = try prefixedPath(alloc, root_prefix, b.dest);
                defer alloc.free(dest);
                try ensurePath(dest);
                try mountPath(src, dest, null, BIND_FLAGS, null, error.BindMount);
                try hardenBindMount(dest, true, false);
                std.fs.deleteFileAbsolute(src) catch {};
                data_bind_counter += 1;
            },
            .file => |f| {
                const full = try prefixedPath(alloc, root_prefix, f.path);
                defer alloc.free(full);
                const parent = std.fs.path.dirname(full);
                if (parent) |p| try ensurePath(p);

                var file = try std.fs.createFileAbsolute(full, .{ .truncate = true });
                defer file.close();
                try file.writeAll(f.data);
                if (takeMode(&current_mode)) |mode| {
                    try std.posix.fchmodat(std.posix.AT.FDCWD, full, @intCast(mode), 0);
                }
            },
            .bind_data_fd => |b| {
                const src = try writeDataSourceFromFd(instance_id, b.fd, data_bind_counter);
                defer alloc.free(src);

                const dest = try prefixedPath(alloc, root_prefix, b.dest);
                defer alloc.free(dest);
                try ensurePath(dest);
                try mountPath(src, dest, null, BIND_FLAGS, null, error.BindMount);
                try hardenBindMount(dest, false, false);
                std.fs.deleteFileAbsolute(src) catch {};
                data_bind_counter += 1;
            },
            .ro_bind_data_fd => |b| {
                const src = try writeDataSourceFromFd(instance_id, b.fd, data_bind_counter);
                defer alloc.free(src);

                const dest = try prefixedPath(alloc, root_prefix, b.dest);
                defer alloc.free(dest);
                try ensurePath(dest);
                try mountPath(src, dest, null, BIND_FLAGS, null, error.BindMount);
                try hardenBindMount(dest, true, false);
                std.fs.deleteFileAbsolute(src) catch {};
                data_bind_counter += 1;
            },
            .file_fd => |f| {
                const full = try prefixedPath(alloc, root_prefix, f.path);
                defer alloc.free(full);
                const parent = std.fs.path.dirname(full);
                if (parent) |p| try ensurePath(p);

                var out_file = try std.fs.createFileAbsolute(full, .{ .truncate = true });
                defer out_file.close();

                var in_file = std.fs.File{ .handle = f.fd };
                var buf: [4096]u8 = undefined;
                while (true) {
                    const n = try in_file.read(&buf);
                    if (n == 0) break;
                    try out_file.writeAll(buf[0..n]);
                }

                if (takeMode(&current_mode)) |mode| {
                    try std.posix.fchmodat(std.posix.AT.FDCWD, full, @intCast(mode), 0);
                }
            },
        }
    }

    if (tmp_overlay_base_ready) {
        const tmp_overlay_root = try prefixedPath(alloc, root_prefix, TMP_OVERLAY_BASE);
        defer alloc.free(tmp_overlay_root);
        teardownTmpOverlayBase(tmp_overlay_root);
    }
}

fn prefixedPath(alloc: std.mem.Allocator, prefix: []const u8, path: []const u8) ![]u8 {
    return std.fmt.allocPrint(alloc, "{s}{s}", .{ prefix, path });
}

pub fn execute(instance_id: []const u8, actions: []const FsAction) !void {
    var overlay_sources = std.ArrayList(OverlaySource).empty;
    defer overlay_sources.deinit(std.heap.page_allocator);
    var tmp_overlay_counter: usize = 0;
    var data_bind_counter: usize = 0;
    var current_mode: ?u32 = null;
    var current_size: ?usize = null;
    var mounted_targets = std.ArrayList(MountedTarget).empty;
    defer mounted_targets.deinit(std.heap.page_allocator);
    var tmp_overlay_base_ready = false;

    var temp_files = std.ArrayList([]const u8).empty;
    defer {
        for (temp_files.items) |p| {
            std.heap.page_allocator.free(p);
        }
        temp_files.deinit(std.heap.page_allocator);
    }

    var temp_dirs = std.ArrayList([]const u8).empty;
    defer {
        for (temp_dirs.items) |p| {
            std.heap.page_allocator.free(p);
        }
        temp_dirs.deinit(std.heap.page_allocator);
    }

    errdefer rollbackMounts(mounted_targets.items);
    errdefer cleanupTempFiles(temp_files.items);
    errdefer cleanupTempDirs(temp_dirs.items);

    for (actions) |action| {
        switch (action) {
            .perms => |mode| {
                current_mode = mode;
            },
            .size => |size_bytes| {
                current_size = size_bytes;
            },
            .bind => |mount_pair| {
                try ensurePath(mount_pair.dest);
                const flags = BIND_FLAGS;
                try mountPath(mount_pair.src, mount_pair.dest, null, flags, null, error.BindMount);
                try hardenBindMount(mount_pair.dest, false, false);
                try mounted_targets.append(std.heap.page_allocator, .{ .path = mount_pair.dest });
            },
            .bind_try => |mount_pair| {
                if (!sourceExists(mount_pair.src)) continue;
                try ensurePath(mount_pair.dest);
                const flags = BIND_FLAGS;
                try mountPath(mount_pair.src, mount_pair.dest, null, flags, null, error.BindMount);
                try hardenBindMount(mount_pair.dest, false, false);
                try mounted_targets.append(std.heap.page_allocator, .{ .path = mount_pair.dest });
            },
            .dev_bind => |mount_pair| {
                try ensurePath(mount_pair.dest);
                const flags = BIND_FLAGS;
                try mountPath(mount_pair.src, mount_pair.dest, null, flags, null, error.BindMount);
                try hardenBindMount(mount_pair.dest, false, true);
                try mounted_targets.append(std.heap.page_allocator, .{ .path = mount_pair.dest });
            },
            .dev_bind_try => |mount_pair| {
                if (!sourceExists(mount_pair.src)) continue;
                try ensurePath(mount_pair.dest);
                const flags = BIND_FLAGS;
                try mountPath(mount_pair.src, mount_pair.dest, null, flags, null, error.BindMount);
                try hardenBindMount(mount_pair.dest, false, true);
                try mounted_targets.append(std.heap.page_allocator, .{ .path = mount_pair.dest });
            },
            .ro_bind => |mount_pair| {
                try ensurePath(mount_pair.dest);
                const bind_flags = BIND_FLAGS;
                try mountPath(mount_pair.src, mount_pair.dest, null, bind_flags, null, error.BindMount);
                try mounted_targets.append(std.heap.page_allocator, .{ .path = mount_pair.dest });
                try hardenBindMount(mount_pair.dest, true, false);
            },
            .ro_bind_try => |mount_pair| {
                if (!sourceExists(mount_pair.src)) continue;
                try ensurePath(mount_pair.dest);
                const bind_flags = BIND_FLAGS;
                try mountPath(mount_pair.src, mount_pair.dest, null, bind_flags, null, error.BindMount);
                try mounted_targets.append(std.heap.page_allocator, .{ .path = mount_pair.dest });
                try hardenBindMount(mount_pair.dest, true, false);
            },
            .proc => |dest| {
                if (std.mem.eql(u8, dest, "/proc")) {
                    continue;
                }
                try ensurePath(dest);
                try mountPath("proc", dest, "proc", PROC_FLAGS, null, error.MountProc);
                try mounted_targets.append(std.heap.page_allocator, .{ .path = dest });
            },
            .dev => |dest| {
                try setupMinimalDevFs(dest);
                try mounted_targets.append(std.heap.page_allocator, .{ .path = dest });
            },
            .mqueue => |dest| {
                try ensurePath(dest);
                try mountPath("mqueue", dest, "mqueue", 0, null, error.MountMqueue);
                try mounted_targets.append(std.heap.page_allocator, .{ .path = dest });
            },
            .tmpfs => |tmpfs| {
                try ensurePath(tmpfs.dest);

                const eff_tmpfs = effectiveTmpfs(tmpfs, current_size, current_mode);
                if (tmpfs.size_bytes == null and eff_tmpfs.size_bytes != null) {
                    current_size = null;
                }
                if (tmpfs.mode == null and eff_tmpfs.mode != null) {
                    current_mode = null;
                }

                var opts_buf: [64]u8 = undefined;
                const opts = if (eff_tmpfs.size_bytes != null or eff_tmpfs.mode != null)
                    try formatTmpfsOpts(&opts_buf, eff_tmpfs)
                else
                    null;

                try mountPath("tmpfs", eff_tmpfs.dest, "tmpfs", TMPFS_FLAGS, opts, error.MountTmpFs);
                try mounted_targets.append(std.heap.page_allocator, .{ .path = eff_tmpfs.dest });
            },
            .dir => |dir_action| {
                try ensurePath(dir_action.path);
                const mode = dir_action.mode orelse takeMode(&current_mode);
                if (mode) |m| {
                    try std.posix.fchmodat(std.posix.AT.FDCWD, dir_action.path, @intCast(m), 0);
                }
            },
            .symlink => |symlink| {
                const parent = std.fs.path.dirname(symlink.path);
                if (parent) |p| {
                    try ensurePath(p);
                }
                std.fs.cwd().symLink(symlink.target, trimPath(symlink.path), .{}) catch |err| switch (err) {
                    error.PathAlreadyExists => {},
                    else => return err,
                };
            },
            .chmod => |chmod_action| {
                try std.posix.fchmodat(std.posix.AT.FDCWD, chmod_action.path, @intCast(chmod_action.mode), 0);
            },
            .remount_ro => |dest| {
                const flags = linux.MS.REMOUNT | linux.MS.RDONLY | linux.MS.NOSUID | linux.MS.NODEV;
                try mountPath(null, dest, null, flags, null, error.RemountReadOnly);
            },
            .overlay_src => |src| {
                try overlay_sources.append(std.heap.page_allocator, src);
            },
            .overlay => |o| {
                const lower = findOverlaySource(overlay_sources.items, o.source_key) orelse return error.MissingOverlaySource;

                try ensurePath(o.dest);
                try ensurePath(o.upper);
                try ensurePath(o.work);

                var opts_buf: [std.posix.PATH_MAX - 1]u8 = undefined;
                const opts = try std.fmt.bufPrint(&opts_buf, "lowerdir={s},upperdir={s},workdir={s}", .{ lower, o.upper, o.work });
                try mountPath("overlay", o.dest, "overlay", 0, opts, error.MountOverlay);
                try mounted_targets.append(std.heap.page_allocator, .{ .path = o.dest });
            },
            .tmp_overlay => |o| {
                const lower = findOverlaySource(overlay_sources.items, o.source_key) orelse return error.MissingOverlaySource;

                try ensurePath(o.dest);

                if (!tmp_overlay_base_ready) {
                    try ensurePath(TMP_OVERLAY_BASE);
                    try mountPath("tmpfs", TMP_OVERLAY_BASE, "tmpfs", TMPFS_FLAGS, null, error.MountTmpFs);
                    try mounted_targets.append(std.heap.page_allocator, .{ .path = TMP_OVERLAY_BASE });
                    tmp_overlay_base_ready = true;
                }

                const overlay_base = try std.fmt.allocPrint(std.heap.page_allocator, "{s}/{s}/{s}-{d}", .{ TMP_OVERLAY_BASE, instance_id, o.source_key, tmp_overlay_counter });
                defer std.heap.page_allocator.free(overlay_base);
                try temp_dirs.append(std.heap.page_allocator, try std.heap.page_allocator.dupe(u8, overlay_base));
                const upper = try std.fmt.allocPrint(std.heap.page_allocator, "{s}/upper", .{overlay_base});
                defer std.heap.page_allocator.free(upper);
                const work = try std.fmt.allocPrint(std.heap.page_allocator, "{s}/work", .{overlay_base});
                defer std.heap.page_allocator.free(work);

                try ensurePath(upper);
                try ensurePath(work);

                var opts_buf: [std.posix.PATH_MAX - 1]u8 = undefined;
                const opts = try std.fmt.bufPrint(&opts_buf, "lowerdir={s},upperdir={s},workdir={s}", .{ lower, upper, work });
                try mountPath("overlay", o.dest, "overlay", 0, opts, error.MountOverlay);
                try mounted_targets.append(std.heap.page_allocator, .{ .path = o.dest });
                tmp_overlay_counter += 1;
            },
            .ro_overlay => |o| {
                const lower = findOverlaySource(overlay_sources.items, o.source_key) orelse return error.MissingOverlaySource;

                try ensurePath(o.dest);

                var opts_buf: [std.posix.PATH_MAX - 1]u8 = undefined;
                const opts = try std.fmt.bufPrint(&opts_buf, "lowerdir={s}", .{lower});
                try mountPath("overlay", o.dest, "overlay", linux.MS.RDONLY, opts, error.MountOverlay);
                try mounted_targets.append(std.heap.page_allocator, .{ .path = o.dest });
            },
            .bind_data => |b| {
                const src = try writeDataSource(instance_id, b.data, data_bind_counter);
                defer std.heap.page_allocator.free(src);
                try temp_files.append(std.heap.page_allocator, try std.heap.page_allocator.dupe(u8, src));

                try ensurePath(b.dest);
                const flags = BIND_FLAGS;
                try mountPath(src, b.dest, null, flags, null, error.BindMount);
                try hardenBindMount(b.dest, false, false);
                try mounted_targets.append(std.heap.page_allocator, .{ .path = b.dest });
                std.fs.deleteFileAbsolute(src) catch {};
                data_bind_counter += 1;
            },
            .ro_bind_data => |b| {
                const src = try writeDataSource(instance_id, b.data, data_bind_counter);
                defer std.heap.page_allocator.free(src);
                try temp_files.append(std.heap.page_allocator, try std.heap.page_allocator.dupe(u8, src));

                try ensurePath(b.dest);
                const bind_flags = BIND_FLAGS;
                try mountPath(src, b.dest, null, bind_flags, null, error.BindMount);
                try mounted_targets.append(std.heap.page_allocator, .{ .path = b.dest });
                try hardenBindMount(b.dest, true, false);
                std.fs.deleteFileAbsolute(src) catch {};
                data_bind_counter += 1;
            },
            .file => |f| {
                const parent = std.fs.path.dirname(f.path);
                if (parent) |p| {
                    try ensurePath(p);
                }

                var file = try std.fs.cwd().createFile(trimPath(f.path), .{ .truncate = true });
                defer file.close();
                try file.writeAll(f.data);
                if (takeMode(&current_mode)) |mode| {
                    try std.posix.fchmodat(std.posix.AT.FDCWD, f.path, @intCast(mode), 0);
                }
            },
            .bind_data_fd => |b| {
                const src = try writeDataSourceFromFd(instance_id, b.fd, data_bind_counter);
                defer std.heap.page_allocator.free(src);
                try temp_files.append(std.heap.page_allocator, try std.heap.page_allocator.dupe(u8, src));

                try ensurePath(b.dest);
                const flags = BIND_FLAGS;
                try mountPath(src, b.dest, null, flags, null, error.BindMount);
                try hardenBindMount(b.dest, false, false);
                try mounted_targets.append(std.heap.page_allocator, .{ .path = b.dest });
                std.fs.deleteFileAbsolute(src) catch {};
                data_bind_counter += 1;
            },
            .ro_bind_data_fd => |b| {
                const src = try writeDataSourceFromFd(instance_id, b.fd, data_bind_counter);
                defer std.heap.page_allocator.free(src);
                try temp_files.append(std.heap.page_allocator, try std.heap.page_allocator.dupe(u8, src));

                try ensurePath(b.dest);
                const bind_flags = BIND_FLAGS;
                try mountPath(src, b.dest, null, bind_flags, null, error.BindMount);
                try mounted_targets.append(std.heap.page_allocator, .{ .path = b.dest });
                try hardenBindMount(b.dest, true, false);
                std.fs.deleteFileAbsolute(src) catch {};
                data_bind_counter += 1;
            },
            .file_fd => |f| {
                const parent = std.fs.path.dirname(f.path);
                if (parent) |p| {
                    try ensurePath(p);
                }

                var out_file = try std.fs.cwd().createFile(trimPath(f.path), .{ .truncate = true });
                defer out_file.close();

                var in_file = std.fs.File{ .handle = f.fd };
                var buf: [4096]u8 = undefined;
                while (true) {
                    const n = try in_file.read(&buf);
                    if (n == 0) break;
                    try out_file.writeAll(buf[0..n]);
                }

                if (takeMode(&current_mode)) |mode| {
                    try std.posix.fchmodat(std.posix.AT.FDCWD, f.path, @intCast(mode), 0);
                }
            },
        }
    }

    if (tmp_overlay_base_ready) {
        teardownTmpOverlayBase(TMP_OVERLAY_BASE);
    }
}

fn takeMode(mode_ptr: *?u32) ?u32 {
    const v = mode_ptr.*;
    mode_ptr.* = null;
    return v;
}

fn effectiveTmpfs(tmpfs: TmpfsMount, size_fallback: ?usize, mode_fallback: ?u32) TmpfsMount {
    return .{
        .dest = tmpfs.dest,
        .size_bytes = tmpfs.size_bytes orelse size_fallback,
        .mode = tmpfs.mode orelse mode_fallback,
    };
}

fn rollbackMounts(mounted_targets: []const MountedTarget) void {
    var i = mounted_targets.len;
    while (i > 0) {
        i -= 1;
        var path_z = std.posix.toPosixPath(mounted_targets[i].path) catch continue;
        _ = linux.umount2(&path_z, linux.MNT.DETACH);
    }
}

fn cleanupTempFiles(paths: []const []const u8) void {
    for (paths) |p| {
        std.fs.deleteFileAbsolute(p) catch {};
    }
}

fn cleanupTempDirs(paths: []const []const u8) void {
    var i = paths.len;
    while (i > 0) {
        i -= 1;
        std.fs.deleteTreeAbsolute(paths[i]) catch {};
    }
}

pub fn cleanupInstanceArtifacts(rootfs: []const u8, instance_id: []const u8) void {
    const data_path = rootedPath(std.heap.page_allocator, rootfs, "/tmp/.libvoid-data", instance_id) catch return;
    cleanupTree(data_path);

    const overlay_path = rootedPath(std.heap.page_allocator, rootfs, "/tmp/.libvoid-overlay", instance_id) catch return;
    cleanupTree(overlay_path);

    const tmp_overlay_path = rootedPath(std.heap.page_allocator, rootfs, TMP_OVERLAY_BASE, instance_id) catch return;
    cleanupTree(tmp_overlay_path);
}

fn cleanupTree(path: []u8) void {
    defer std.heap.page_allocator.free(path);
    std.fs.deleteTreeAbsolute(path) catch {};
}

fn teardownTmpOverlayBase(path: []const u8) void {
    var path_z = std.posix.toPosixPath(path) catch return;
    _ = linux.umount2(&path_z, linux.MNT.DETACH);
    std.fs.deleteTreeAbsolute(path) catch {};
}

fn rootedPath(allocator: std.mem.Allocator, rootfs: []const u8, base: []const u8, child: []const u8) ![]u8 {
    if (std.mem.eql(u8, rootfs, "/")) {
        return std.fs.path.join(allocator, &.{ base, child });
    }
    return std.fs.path.join(allocator, &.{ rootfs, trimPath(base), child });
}

fn writeDataSource(instance_id: []const u8, data: []const u8, index: usize) ![]const u8 {
    const path = try std.fmt.allocPrint(std.heap.page_allocator, "/tmp/.libvoid-data/{s}/{d}", .{ instance_id, index });
    errdefer std.heap.page_allocator.free(path);
    const parent = std.fs.path.dirname(path);
    if (parent) |p| {
        try ensurePath(p);
    }

    var file = try std.fs.createFileAbsolute(path, .{ .truncate = true });
    defer file.close();
    errdefer std.fs.deleteFileAbsolute(path) catch {};
    try file.writeAll(data);
    return path;
}

fn writeDataSourceFromFd(instance_id: []const u8, fd: i32, index: usize) ![]const u8 {
    const path = try std.fmt.allocPrint(std.heap.page_allocator, "/tmp/.libvoid-data/{s}/{d}", .{ instance_id, index });
    errdefer std.heap.page_allocator.free(path);
    const parent = std.fs.path.dirname(path);
    if (parent) |p| {
        try ensurePath(p);
    }

    var out_file = try std.fs.createFileAbsolute(path, .{ .truncate = true });
    defer out_file.close();
    errdefer std.fs.deleteFileAbsolute(path) catch {};
    var in_file = std.fs.File{ .handle = fd };

    var buf: [4096]u8 = undefined;
    while (true) {
        const n = try in_file.read(&buf);
        if (n == 0) break;
        try out_file.writeAll(buf[0..n]);
    }
    return path;
}

fn findOverlaySource(sources: []const OverlaySource, key: []const u8) ?[]const u8 {
    for (sources) |src| {
        if (std.mem.eql(u8, src.key, key)) return src.path;
    }
    return null;
}

fn sourceExists(path: []const u8) bool {
    std.posix.access(path, std.posix.F_OK) catch return false;
    return true;
}

fn formatTmpfsOpts(buffer: []u8, tmpfs: @import("config.zig").TmpfsMount) ![]const u8 {
    if (tmpfs.size_bytes) |size| {
        if (tmpfs.mode) |mode| {
            return std.fmt.bufPrint(buffer, "size={},mode={o}", .{ size, mode });
        }
        return std.fmt.bufPrint(buffer, "size={}", .{size});
    }

    return std.fmt.bufPrint(buffer, "mode={o}", .{tmpfs.mode.?});
}

fn ensurePath(path: []const u8) !void {
    const normalized = trimPath(path);
    if (normalized.len == 0) return;

    if (std.mem.startsWith(u8, path, "/")) {
        var root = try std.fs.openDirAbsolute("/", .{});
        defer root.close();
        try root.makePath(normalized);
        return;
    }

    try std.fs.cwd().makePath(normalized);
}

fn trimPath(path: []const u8) []const u8 {
    return std.mem.trimLeft(u8, path, "/");
}

fn hardenBindMount(dest: []const u8, readonly: bool, allow_devices: bool) !void {
    var flags: u32 = if (allow_devices) BIND_HARDEN_DEV_FLAGS else BIND_HARDEN_FLAGS;
    if (readonly) flags |= linux.MS.RDONLY;
    try mountPath(null, dest, null, flags, null, error.RemountReadOnly);
}

fn hardenProcBind(dest: []const u8) !void {
    const flags = linux.MS.BIND | linux.MS.REMOUNT | linux.MS.REC | linux.MS.NOSUID | linux.MS.NODEV | linux.MS.NOEXEC;
    try mountPath(null, dest, null, flags, null, error.RemountReadOnly);
}

fn setupMinimalDevFs(dest: []const u8) !void {
    try ensurePath(dest);

    var tmpfs_opts_buf: [32]u8 = undefined;
    const tmpfs_opts = try std.fmt.bufPrint(&tmpfs_opts_buf, "mode=755", .{});
    try mountPath("tmpfs", dest, "tmpfs", TMPFS_FLAGS, tmpfs_opts, error.MountTmpFs);

    const pts_path = try std.fmt.allocPrint(std.heap.page_allocator, "{s}/pts", .{dest});
    defer std.heap.page_allocator.free(pts_path);
    try ensurePath(pts_path);

    var devpts_opts_buf: [64]u8 = undefined;
    const devpts_opts = try std.fmt.bufPrint(&devpts_opts_buf, "newinstance,ptmxmode=0666,mode=620", .{});
    try mountPath("devpts", pts_path, "devpts", linux.MS.NOSUID | linux.MS.NOEXEC, devpts_opts, error.MountDevTmpFs);

    const shm_path = try std.fmt.allocPrint(std.heap.page_allocator, "{s}/shm", .{dest});
    defer std.heap.page_allocator.free(shm_path);
    try ensurePath(shm_path);
    var shm_opts_buf: [64]u8 = undefined;
    const shm_opts = try std.fmt.bufPrint(&shm_opts_buf, "mode=1777,size=65536k", .{});
    try mountPath("tmpfs", shm_path, "tmpfs", TMPFS_FLAGS, shm_opts, error.MountTmpFs);

    try bindDeviceNode(dest, "/dev/null", "null");
    try bindDeviceNode(dest, "/dev/zero", "zero");
    try bindDeviceNode(dest, "/dev/full", "full");
    try bindDeviceNode(dest, "/dev/random", "random");
    try bindDeviceNode(dest, "/dev/urandom", "urandom");
    try bindDeviceNode(dest, "/dev/tty", "tty");
    try bindDeviceNode(dest, "/dev/ptmx", "ptmx");
}

fn bindDeviceNode(dev_root: []const u8, src: []const u8, name: []const u8) !void {
    const target = try std.fmt.allocPrint(std.heap.page_allocator, "{s}/{s}", .{ dev_root, name });
    defer std.heap.page_allocator.free(target);
    {
        var file = try std.fs.createFileAbsolute(target, .{ .read = true, .truncate = false });
        file.close();
    }
    try mountPath(src, target, null, BIND_FLAGS, null, error.BindMount);
    try hardenBindMount(target, false, true);
}

fn mountPath(
    special: ?[]const u8,
    dir: []const u8,
    fstype: ?[]const u8,
    flags: u32,
    data: ?[]const u8,
    err_ty: anytype,
) !void {
    var dir_z = try std.posix.toPosixPath(dir);

    var special_z: [std.posix.PATH_MAX - 1:0]u8 = undefined;
    const special_ptr = if (special) |s| blk: {
        special_z = try std.posix.toPosixPath(s);
        break :blk @as([*:0]const u8, &special_z);
    } else null;

    var fstype_z: [std.posix.PATH_MAX - 1:0]u8 = undefined;
    const fstype_ptr = if (fstype) |s| blk: {
        fstype_z = try std.posix.toPosixPath(s);
        break :blk @as([*:0]const u8, &fstype_z);
    } else null;

    var data_z: [std.posix.PATH_MAX - 1:0]u8 = undefined;
    const data_ptr = if (data) |d| blk: {
        data_z = try std.posix.toPosixPath(d);
        break :blk @as([*:0]const u8, &data_z);
    } else null;

    try checkErrAllowBusy(linux.mount(special_ptr, &dir_z, fstype_ptr, flags, if (data_ptr) |p| @intFromPtr(p) else 0), err_ty);
}

test "trimPath strips leading slashes" {
    try std.testing.expectEqualStrings("tmp/a", trimPath("/tmp/a"));
    try std.testing.expectEqualStrings("tmp/a", trimPath("////tmp/a"));
    try std.testing.expectEqualStrings("", trimPath("/"));
}

test "formatTmpfsOpts formats size and mode" {
    var buf: [64]u8 = undefined;
    const opts = try formatTmpfsOpts(&buf, .{ .dest = "/tmp", .size_bytes = 1024, .mode = 0o700 });
    try std.testing.expectEqualStrings("size=1024,mode=700", opts);
}

test "bind hardening flags include recursive remount" {
    try std.testing.expect((BIND_HARDEN_FLAGS & linux.MS.REC) != 0);
    try std.testing.expect((BIND_HARDEN_DEV_FLAGS & linux.MS.REC) != 0);
}

test "findOverlaySource resolves source by key" {
    const sources = [_]OverlaySource{
        .{ .key = "base", .path = "/layers/base" },
        .{ .key = "dev", .path = "/layers/dev" },
    };

    try std.testing.expectEqualStrings("/layers/dev", findOverlaySource(&sources, "dev").?);
    try std.testing.expect(findOverlaySource(&sources, "none") == null);
}

test "sourceExists handles existing and missing paths" {
    try std.testing.expect(sourceExists("/"));
    try std.testing.expect(!sourceExists("/definitely/not/a/real/path"));
}

test "ensurePath creates absolute directories" {
    const path = "/tmp/libvoid-ensure-path-abs-test/a/b";
    std.fs.deleteTreeAbsolute("/tmp/libvoid-ensure-path-abs-test") catch {};
    defer std.fs.deleteTreeAbsolute("/tmp/libvoid-ensure-path-abs-test") catch {};

    try ensurePath(path);
    try std.testing.expect(sourceExists(path));
}

test "effectiveTmpfs applies size and mode modifiers" {
    const resolved = effectiveTmpfs(.{ .dest = "/tmp" }, 2048, 0o755);
    try std.testing.expectEqual(@as(?usize, 2048), resolved.size_bytes);
    try std.testing.expectEqual(@as(?u32, 0o755), resolved.mode);

    const explicit = effectiveTmpfs(.{ .dest = "/tmp", .size_bytes = 4096, .mode = 0o700 }, 2048, 0o755);
    try std.testing.expectEqual(@as(?usize, 4096), explicit.size_bytes);
    try std.testing.expectEqual(@as(?u32, 0o700), explicit.mode);
}

test "takeMode is one-shot" {
    var mode: ?u32 = 0o755;
    try std.testing.expectEqual(@as(?u32, 0o755), takeMode(&mode));
    try std.testing.expectEqual(@as(?u32, null), takeMode(&mode));
}

test "bind_try skips missing source without failing" {
    const actions = [_]FsAction{
        .{ .bind_try = .{ .src = "/definitely/not/a/real/path", .dest = "/tmp/libvoid-bind-try-skip" } },
    };

    try execute("itest", &actions);
}

test "dev_bind_try skips missing source without failing" {
    const actions = [_]FsAction{
        .{ .dev_bind_try = .{ .src = "/definitely/not/a/real/path", .dest = "/tmp/libvoid-dev-bind-try-skip" } },
    };

    try execute("itest", &actions);
}

test "ro_bind_try skips missing source without failing" {
    const actions = [_]FsAction{
        .{ .ro_bind_try = .{ .src = "/definitely/not/a/real/path", .dest = "/tmp/libvoid-ro-bind-try-skip" } },
    };

    try execute("itest", &actions);
}

test "rootedPath maps chroot paths to host paths" {
    const p1 = try rootedPath(std.testing.allocator, "/", "/tmp/.libvoid-data", "abc");
    defer std.testing.allocator.free(p1);
    try std.testing.expectEqualStrings("/tmp/.libvoid-data/abc", p1);

    const p2 = try rootedPath(std.testing.allocator, "/srv/rootfs", "/tmp/.libvoid-overlay", "xyz");
    defer std.testing.allocator.free(p2);
    try std.testing.expectEqualStrings("/srv/rootfs/tmp/.libvoid-overlay/xyz", p2);
}

test "cleanupInstanceArtifacts removes data and overlay trees" {
    const instance_id = "itest-cleanup-artifacts";

    const data_dir = try std.fmt.allocPrint(std.testing.allocator, "/tmp/.libvoid-data/{s}", .{instance_id});
    defer std.testing.allocator.free(data_dir);
    const overlay_dir = try std.fmt.allocPrint(std.testing.allocator, "/tmp/.libvoid-overlay/{s}", .{instance_id});
    defer std.testing.allocator.free(overlay_dir);

    std.fs.deleteTreeAbsolute(data_dir) catch {};
    std.fs.deleteTreeAbsolute(overlay_dir) catch {};
    try ensurePath(data_dir);
    try ensurePath(overlay_dir);

    cleanupInstanceArtifacts("/", instance_id);

    try std.testing.expect(!sourceExists(data_dir));
    try std.testing.expect(!sourceExists(overlay_dir));
}

test "cleanup helpers remove temporary files and directories" {
    const file_path = "/tmp/libvoid-cleanup-helper-file";
    const dir_path = "/tmp/libvoid-cleanup-helper-dir";

    std.fs.deleteFileAbsolute(file_path) catch {};
    std.fs.deleteTreeAbsolute(dir_path) catch {};

    {
        var file = try std.fs.createFileAbsolute(file_path, .{ .truncate = true });
        file.close();
    }
    try ensurePath(dir_path);

    cleanupTempFiles(&.{file_path});
    cleanupTempDirs(&.{dir_path});

    try std.testing.expect(!sourceExists(file_path));
    try std.testing.expect(!sourceExists(dir_path));
}

test "execute cleans bind-data temp file on mount failure" {
    const instance_id = "itest-bind-data-rollback";
    const temp_source = "/tmp/.libvoid-data/itest-bind-data-rollback/0";

    std.fs.deleteFileAbsolute(temp_source) catch {};

    const actions = [_]FsAction{
        .{ .bind_data = .{ .data = "hello", .dest = "/tmp/libvoid-bind-data-fail" } },
    };

    try std.testing.expectError(error.BindMount, execute(instance_id, &actions));
    try std.testing.expect(!sourceExists(temp_source));
    cleanupInstanceArtifacts("/", instance_id);
}

test "execute cleans tmp-overlay temp dirs on overlay mount failure" {
    const instance_id = "itest-tmp-overlay-rollback";
    const overlay_base = "/tmp/.libvoid-tmp-overlay/itest-tmp-overlay-rollback/base-0";

    std.fs.deleteTreeAbsolute(overlay_base) catch {};

    const actions = [_]FsAction{
        .{ .overlay_src = .{ .key = "base", .path = "/definitely/not/a/real/lowerdir" } },
        .{ .tmp_overlay = .{ .source_key = "base", .dest = "/tmp/libvoid-overlay-fail" } },
    };

    const result = execute(instance_id, &actions);
    _ = result catch |err| switch (err) {
        error.MountOverlay, error.MountTmpFs => {},
        else => return err,
    };
    try std.testing.expect(!sourceExists(overlay_base));
    cleanupInstanceArtifacts("/", instance_id);
}

test "writeDataSourceFromFd cleans temporary file on read failure" {
    const instance_id = "itest-write-fd-cleanup";
    const leaked_path = try std.fmt.allocPrint(std.testing.allocator, "/tmp/.libvoid-data/{s}/{d}", .{ instance_id, 0 });
    defer std.testing.allocator.free(leaked_path);

    std.fs.deleteFileAbsolute(leaked_path) catch {};

    _ = writeDataSourceFromFd(instance_id, -1, 0) catch {};
    try std.testing.expect(!sourceExists(leaked_path));
    cleanupInstanceArtifacts("/", instance_id);
}
