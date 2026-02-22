const std = @import("std");
const linux = std.os.linux;
const utils = @import("utils.zig");
const ResourceArgs = @import("config.zig").ResourceLimits;

const Resource = enum {
    cpu,
    memory,
    pids,

    fn max(self: Resource) []const u8 {
        return switch (self) {
            inline else => |v| @tagName(v) ++ ".max",
        };
    }
};

/// container id
cid: []const u8,
options: ResourceArgs,
allocator: std.mem.Allocator,
enabled: bool,

const Cgroup = @This();

pub fn init(cid: []const u8, options: ResourceArgs, allocator: std.mem.Allocator) !Cgroup {
    const enabled = options.mem != null or options.cpu != null or options.pids != null;
    var cgroups = Cgroup{
        .cid = cid,
        .options = options,
        .allocator = allocator,
        .enabled = enabled,
    };

    if (!enabled) return cgroups;

    try cgroups.initDirs();
    try cgroups.applyResourceLimits();
    return cgroups;
}

fn applyResourceLimits(self: *Cgroup) !void {
    if (self.options.mem) |val| {
        try self.setResourceMax(.memory, val);
    }

    if (self.options.cpu) |val| {
        try self.setResourceMax(.cpu, val);
    }

    if (self.options.pids) |val| {
        try self.setResourceMax(.pids, val);
    }
}

fn initDirs(self: *Cgroup) !void {
    const path = try std.mem.concat(self.allocator, u8, &.{ utils.CGROUP_PATH ++ "libvoid/", self.cid });
    defer self.allocator.free(path);
    _ = try utils.createDirIfNotExists(path);
}

pub fn setResourceMax(self: *Cgroup, resource: Resource, limit: []const u8) !void {
    const path = try std.mem.concat(self.allocator, u8, &.{ utils.CGROUP_PATH, "libvoid/", self.cid, "/", resource.max() });
    defer self.allocator.free(path);
    var file = try std.fs.openFileAbsolute(path, .{ .mode = .read_write });
    defer file.close();
    try file.writeAll(limit);
}

pub fn enterCgroup(self: *Cgroup, pid: linux.pid_t) !void {
    if (!self.enabled) return;

    const cgroup_path = try std.mem.concat(self.allocator, u8, &.{ utils.CGROUP_PATH, "libvoid/", self.cid, "/cgroup.procs" });
    defer self.allocator.free(cgroup_path);
    const file = try std.fs.openFileAbsolute(cgroup_path, .{ .mode = .write_only });
    defer file.close();
    var pid_buff: [32]u8 = undefined;
    const pid_str = try std.fmt.bufPrint(&pid_buff, "{}", .{pid});
    try file.writeAll(pid_str);
}

pub fn deinit(self: *Cgroup) !void {
    if (!self.enabled) return;

    const path = try std.mem.concat(self.allocator, u8, &.{ utils.CGROUP_PATH ++ "libvoid/", self.cid });
    defer self.allocator.free(path);
    try std.fs.deleteDirAbsolute(path);
}
