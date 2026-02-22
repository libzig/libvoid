const std = @import("std");
const utils = @import("utils.zig");

pub const InitWarning = enum {
    RuntimeDirUnavailable,
    ContainersDirUnavailable,
    NetnsDirUnavailable,
    CgroupDirUnavailable,
    CgroupControllerUnavailable,
    CgroupControllerWriteFailed,
};

pub const InitResult = struct {
    warnings: std.EnumSet(InitWarning) = std.EnumSet(InitWarning).initEmpty(),

    pub fn ok(self: InitResult) bool {
        return self.warning_count() == 0;
    }

    pub fn has_warning(self: InitResult, warning: InitWarning) bool {
        return self.warnings.contains(warning);
    }

    pub fn warning_count(self: InitResult) usize {
        return self.warnings.count();
    }
};

pub fn init() InitResult {
    var result = InitResult{};

    _ = ensure_dir("/var/run/libvoid", .RuntimeDirUnavailable, &result);
    _ = ensure_dir("/var/run/libvoid/containers", .ContainersDirUnavailable, &result);
    _ = ensure_dir("/var/run/libvoid/containers/netns", .NetnsDirUnavailable, &result);

    const path = utils.CGROUP_PATH ++ "libvoid/";
    const cgroup_ready = ensure_dir(path, .CgroupDirUnavailable, &result);
    if (!cgroup_ready) return result;

    const root_cgroup = path ++ "cgroup.subtree_control";
    var root_cgroup_file = std.fs.openFileAbsolute(root_cgroup, .{ .mode = .write_only }) catch |err| {
        record_warning(
            &result,
            .CgroupControllerUnavailable,
            "runtime init warning: unable to open {s}: {s}",
            .{ root_cgroup, @errorName(err) },
        );
        return result;
    };
    defer root_cgroup_file.close();

    root_cgroup_file.writeAll("+cpu +memory +pids") catch |err| {
        record_warning(
            &result,
            .CgroupControllerWriteFailed,
            "runtime init warning: unable to enable controllers in {s}: {s}",
            .{ root_cgroup, @errorName(err) },
        );
        return result;
    };

    return result;
}

fn ensure_dir(path: []const u8, warning: InitWarning, result: *InitResult) bool {
    _ = utils.createDirIfNotExists(path) catch |err| {
        record_warning(
            result,
            warning,
            "runtime init warning: unable to prepare {s}: {s}",
            .{ path, @errorName(err) },
        );
        return false;
    };
    return true;
}

fn record_warning(result: *InitResult, warning: InitWarning, comptime fmt: []const u8, args: anytype) void {
    result.warnings.insert(warning);
    std.log.warn(fmt, args);
}

test "init result warning set tracks unique warnings" {
    var result = InitResult{};
    record_warning(&result, .RuntimeDirUnavailable, "runtime init warning test: {s}", .{"first"});
    record_warning(&result, .RuntimeDirUnavailable, "runtime init warning test: {s}", .{"duplicate"});
    record_warning(&result, .CgroupControllerWriteFailed, "runtime init warning test: {s}", .{"other"});

    try std.testing.expect(result.has_warning(.RuntimeDirUnavailable));
    try std.testing.expect(result.has_warning(.CgroupControllerWriteFailed));
    try std.testing.expectEqual(@as(usize, 2), result.warning_count());
    try std.testing.expect(!result.ok());
}
