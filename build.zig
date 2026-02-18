const std = @import("std");

// Although this function looks imperative, note that its job is to
// declaratively construct a build graph that will be executed by an external
// runner.
pub fn build(b: *std.Build) !void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    if (target.result.os.tag != .linux) {
        return error.InvalidOS;
    }

    // Standard optimization options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall. Here we do not
    // set a preferred release mode, allowing the user to decide how to optimize.
    const optimize = b.standardOptimizeOption(.{});

    const voidbox_module = b.createModule(.{
        .root_source_file = b.path("lib/voidbox.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    _ = b.addModule("voidbox", .{
        .root_source_file = b.path("lib/voidbox.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    const lib = b.addLibrary(.{
        .name = "voidbox",
        .root_module = voidbox_module,
        .linkage = .static,
    });

    b.installArtifact(lib);

    const exe_unit_tests = b.addTest(.{
        .root_module = voidbox_module,
    });

    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);

    // Similar to creating the run step earlier, this exposes a `test` step to
    // the `zig build --help` menu, providing a way for the user to request
    // running the unit tests.
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_exe_unit_tests.step);

    const ex_shell_module = b.createModule(.{
        .root_source_file = b.path("examples/embedder_launch_shell.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    ex_shell_module.addImport("voidbox", voidbox_module);

    const ex_shell = b.addExecutable(.{
        .name = "example_embedder_launch_shell",
        .root_module = ex_shell_module,
    });

    const ex_events_module = b.createModule(.{
        .root_source_file = b.path("examples/embedder_events.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    ex_events_module.addImport("voidbox", voidbox_module);

    const ex_events = b.addExecutable(.{
        .name = "example_embedder_events",
        .root_module = ex_events_module,
    });

    const ex_pty_module = b.createModule(.{
        .root_source_file = b.path("examples/embedder_pty_isolation.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    ex_pty_module.addImport("voidbox", voidbox_module);

    const ex_pty = b.addExecutable(.{
        .name = "example_embedder_pty_isolation",
        .root_module = ex_pty_module,
    });

    const ex_showcase_module = b.createModule(.{
        .root_source_file = b.path("examples/embedder_isolation_showcase.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    ex_showcase_module.addImport("voidbox", voidbox_module);

    const ex_showcase = b.addExecutable(.{
        .name = "example_embedder_isolation_showcase",
        .root_module = ex_showcase_module,
    });

    const vb_module = b.createModule(.{
        .root_source_file = b.path("bin/vb.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    vb_module.addImport("voidbox", voidbox_module);

    const vb_unit_tests = b.addTest(.{
        .root_module = vb_module,
    });
    const run_vb_unit_tests = b.addRunArtifact(vb_unit_tests);
    test_step.dependOn(&run_vb_unit_tests.step);

    const vb = b.addExecutable(.{
        .name = "vb",
        .root_module = vb_module,
    });
    b.installArtifact(vb);

    const vb_step = b.step("vb", "Compile vb CLI binary");
    vb_step.dependOn(&vb.step);

    b.installArtifact(ex_pty);

    const ex_landlock_module = b.createModule(.{
        .root_source_file = b.path("examples/embedder_landlock.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    ex_landlock_module.addImport("voidbox", voidbox_module);

    const ex_landlock = b.addExecutable(.{
        .name = "example_embedder_landlock",
        .root_module = ex_landlock_module,
    });

    b.installArtifact(ex_landlock);

    const examples_step = b.step("examples", "Compile embedder examples");
    examples_step.dependOn(&ex_shell.step);
    examples_step.dependOn(&ex_events.step);
    examples_step.dependOn(&ex_pty.step);
    examples_step.dependOn(&ex_showcase.step);
    examples_step.dependOn(&ex_landlock.step);
}
