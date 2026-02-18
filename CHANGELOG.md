# Changelog

## [0.0.10] - 2026-02-18

### <!-- 0 -->⛰️  Features

- Add Landlock CLI flags, try_ support, example, and integration tests
- Integrate Landlock into spawn pipeline and doctor report
- Implement Landlock LSM syscall wrappers and access mode mapping
- Add Landlock config types, validation, and public exports

### <!-- 3 -->📚 Documentation

- Update Landlock LSM and hardening status

## [0.0.9] - 2026-02-17

### <!-- 0 -->⛰️  Features

- Enhance security and filesystem isolation

## [0.0.8] - 2026-02-16

### <!-- 0 -->⛰️  Features

- Improve filesystem isolation flexibility
- Improve user namespace handling and embedder example

## [0.0.7] - 2026-02-16

### <!-- 1 -->🐛 Bug Fixes

- Set UID/GID to 0 inside new user namespace

## [0.0.6] - 2026-02-16

### <!-- 1 -->🐛 Bug Fixes

- Implement user namespace creation and mapping

## [0.0.5] - 2026-02-16

### <!-- 1 -->🐛 Bug Fixes

- Correct order for user namespace mappings

## [0.0.3] - 2026-02-15

### <!-- 0 -->⛰️  Features

- Parse IPv4 destination and preferred source route attrs
- Add bind-fd and ro-bind-fd option support
- Parse security label flags with strict validation
- Add --level-prefix option for diagnostic output
- Refactor CLI argument parsing and add try-options
- Improve user namespace setup and error handling
- Improve CLI usage output and remove doctor command
- Implement bubblewrap-compatible CLI argument parsing
- Add standalone vb cli target
- Implement pidns attach sequencing behavior
- Add runtime uid gid hostname and as-pid1 options
- Make fs perms modifier one-shot
- Run command under pid1 reaper flow
- Add fd-based file and data fs actions
- Enforce runtime userns disable semantics
- Add info-fd and setup-finished status events
- Propagate real child exit codes through library APIs
- Tighten pid namespace attach semantics
- Add fs perms/size modifier semantics
- Add try-bind and mqueue filesystem actions
- Support attaching existing pid namespaces
- Support attaching existing user namespaces
- Add disable/assert user namespace controls
- Add user and cgroup isolation controls
- Add callback status sink abstraction
- Expose typed public error contracts
- Add strict doctor gating mode
- Add machine-readable doctor json output
- Add doctor readiness scoring and recommendations
- Support capability names in CLI flags
- Add CLI overlay filesystem action flags
- Add mount rollback on fs action failures
- Extend doctor with kernel capability matrix
- Add data bind and file fs actions
- Implement overlay filesystem action execution
- Add overlay fs action types and topology checks
- Enrich status stream with ns ids and timestamps
- Add namespace fd attach configuration
- Add args-fd input support for run
- Add lock and fd synchronization controls
- Add JSON status fd event output
- Add CLI filesystem action flags
- Add CLI process and security controls
- Load seccomp filters from inherited fds
- Add seccomp filter stacking semantics
- Add seccomp filter program baseline
- Support capability add/drop sequencing
- Add seccomp strict security mode baseline
- Add capability drop security controls
- Add security options with no-new-privs default
- Strengthen jail configuration validation
- Add ordered filesystem action execution
- Add launch profiles and config validation
- Add process and environment launch options
- Add spawn and wait session APIs
- Add host doctor API and command
- Add initial voidbox library facade
- Renamed project to zspace

### <!-- 1 -->🐛 Bug Fixes

- Reap spawned child on parent-side setup failures
- Close first spawn pipe when second pipe creation fails
- Harden parser string ownership transfer on failures
- Handle absolute fs-action paths without cwd leakage
- Clean temporary data-source files on write/read failures
- Treat missing veth as non-fatal during net teardown
- Avoid double free in instance artifact cleanup
- Free rooted cleanup paths for fs artifacts
- Make IPv4 broadcast math explicit and endian-safe
- Rollback pid1 signal handlers on install failure
- Harden spawn pipe sync reads and writes
- Enforce container sync fd protocol byte
- Only short-circuit link recv when filters are active
- Enforce session sync fd protocol byte value
- Validate container sync fd readiness reads
- Bound netlink ack frame iteration
- Require explicit parent-child setup byte handshake
- Handle iptables child termination statuses safely
- Validate netlink ack error code ranges
- Deinit parsed routes on receive failure
- Fail child setup when readiness signal write is short
- Bound rtnetlink packet receive loops
- Bound rtnetlink attribute parsing loops
- Treat successful route ERROR ack as stream terminator
- Cap link netlink frame parsing
- Cap route dump parsing to bounded message count
- Iterate ACK frames with netlink alignment checks
- Validate sync fd handshakes against short reads
- Match gateway and output interface per route entry
- Use writeAll for cgroup controller initialization
- Refresh cached default interface when link disappears
- Restore pid1 signal handlers after child wait
- Validate expected rtnetlink message types
- Reject non-zero trailing netlink padding
- Parse netlink ACK errors from minimal payloads
- Reject misaligned netlink route frames
- Forward pid1 signals to child process group
- Handle IPv4 address conflicts and improve error checking
- Scope fs temp artifacts per instance and clean on exit
- Surface runtime init degradation with explicit warnings
- Clean up fs action temp artifacts on failure
- Correct ipv4 broadcast calculation endianness
- Emit setup readiness only after child setup completes
- Harden rtnetlink socket and parser bounds checks
- Harden parent spawn resource cleanup
- Generate unique runtime instance ids
- Enforce exclusive lock-file semantics
- Reject dangling perms and size modifiers
- Reject mixed seccomp fd option modes
- Limit try fallback to spawn failures
- Treat unshare-all as user/cgroup try semantics
- Refine userns-try fallback mount behavior
- Support userns proc/dev action flow
- Improve vb runtime parity and test coverage
- Align user namespace and mount defaults
- Avoid setsid when attached to interactive tty

### <!-- 2 -->🚜 Refactor

- Keep parser missing-value handling side-effect free
- Remove unused nlmsgerr wrapper API
- Drop unused network namespace helper
- Remove unused network path constants
- Remove unused netns path allocation in veth setup
- Centralize one-byte sync fd read/write helpers
- Centralize NAT cache reconfigure decision
- Replace placeholder networking semantics with explicit behavior
- Add parser-owned allocation cleanup model
- Rename src to lib and cli to bin
- Scope busy mount handling to fs actions
- Add namespace sequencing module and userns2 semantics
- Decouple process execution and namespace semantics
- Split mount namespace setup into module
- Split networking internals into network module
- Split filesystem action engine into module
- Split namespace and security internals
- Remove CLI sources for library-only project
- Make build library-only and drop CLI artifact
- Extract orchestration into session module

### <!-- 3 -->📚 Documentation

- Expand TLDR with extended cookbook and hardening checklist
- Restore concise README and add detailed TLDR reference
- Expand README with architecture, lifecycle, and troubleshooting
- Add project README with build, test, and usage
- Add current implementation progress snapshot
- Replace ipv6 TODO with explicit parser contract
- Add library embedder examples and quickstart

### <!-- 4 -->⚡ Performance

- Short-circuit link get when filters are provided

### <!-- 6 -->🧪 Testing

- Cover fs rollback cleanup for bind-data and tmp-overlay
- Verify temp file and dir cleanup helpers
- Stress status callback ordering under parallel launches
- Cover parser cleanup for nested --args failures
- Verify instance artifact cleanup removes temp trees
- Verify parser-owned strings clean up on parse errors
- Verify Net init/deinit file descriptor stability
- Cover launch path with as_pid_1 enabled
- Add parallel namespace-toggle integration stress
- Assert pid1 forwarded signal exclusions
- Verify rtnetlink init/deinit fd stability
- Add parallel netless integration stress matrix
- Verify lock file can be reacquired after close
- Release session resources per stress iteration
- Isolate lock file test path per run
- Add sequential session spawn-wait stress cycles
- Enforce single-wait session lifecycle semantics
- Cover netlink ACK error mapping behavior
- Assert status lifecycle event ordering
- Add sequential integration stress launch coverage
- Cover runtime warning status output paths
- Finalize try and unshare-all parity expectations
- Add focused try-flag parser coverage
- Cover cgroup and user try fallback semantics
- Verify ro-bind-try skips missing source
- Verify dev-bind-try skips missing source
- Verify bind-try skips missing source
- Add integration coverage for toggles and cgroups
- Add optional library integration smoke tests
- Cover clone flag composition behavior
- Add compile-time public API contract checks
- Add fs rollback stress coverage
- Verify rollback mount ordering semantics
- Add supervisor fd interoperability checks
- Cover full isolation profile validation

### <!-- 7 -->⚙️ Miscellaneous Tasks

- Add release automation via git-rel
- Stop tracking ignored PLAN.md
- Update LICENSE copyright year
- Update path and bridge name constants

### Rtnetlink

- Support link delete messages
- Support route get request

All notable changes to this project will be documented in this file.
