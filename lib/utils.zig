const std = @import("std");
const linux = std.os.linux;

pub const CGROUP_PATH = "/sys/fs/cgroup/";
pub const INFO_PATH = "/var/run/libvoid/containers/";
pub const NETNS_PATH = INFO_PATH ++ "netns/";
pub const BRIDGE_NAME = "libvoid0";

pub fn checkErr(val: usize, err: anyerror) !void {
    const signed: isize = @bitCast(val);
    if (signed < 0 and signed > -4096) {
        return err;
    }
}

pub fn checkErrAllowBusy(val: usize, err: anyerror) !void {
    const signed: isize = @bitCast(val);
    if (signed < 0 and signed > -4096) {
        const e: std.os.linux.E = @enumFromInt(@as(usize, @intCast(-signed)));
        if (e == .BUSY) return;
        return err;
    }
}

pub fn createDirIfNotExists(path: []const u8) !bool {
    std.fs.makeDirAbsolute(path) catch |e| {
        return switch (e) {
            error.PathAlreadyExists => false,
            else => e,
        };
    };
    return true;
}

pub fn createFileIfNotExists(path: []const u8) !bool {
    const f = std.fs.createFileAbsolute(path, .{ .exclusive = true }) catch |e| {
        return switch (e) {
            error.PathAlreadyExists => false,
            else => e,
        };
    };
    f.close();
    return true;
}
