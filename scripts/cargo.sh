#!/bin/sh
# Run cargo inside the pinned build container.
#
# The host has no rust toolchain on purpose: every build, test, fmt, clippy and metrics run goes
# through this wrapper, so the version is the one pinned in `rust-toolchain.toml` and the image
# built from `docker/toolchain.Dockerfile`. Before this file existed, runs were ad-hoc `docker run`
# commands kept in the shell history, and the difference showed up three ways in one week: a target
# directory nobody pruned (3.5G), debug info at the default level, and a mounted cache directory
# that docker had created as root - the last one failing with
#
#     error: failed to create directory `/cargo/git/db/<crate>-<hash>`
#     Caused by: Permission denied (os error 13)
#
# which reads as a broken dependency rather than as a directory owned by another user.
set -eu

repo=$(cd "$(dirname "$0")/.." && pwd)

# The registry is shared with `rrl-directory` and named after the base it serves: a registry filled
# under one glibc is one the next toolchain may not be able to use, and both crates build on
# bullseye's 2.31 on purpose (the stands and Astra Linux run it). The target directory is *not*
# shared - two crates building into one target directory invalidate each other's fingerprints and
# hold each other's `.cargo-lock`.
cargo_cache="${RR_SMB_CARGO_CACHE:-rrl-cargo-bullseye}"
target_cache="${RR_SMB_TARGET_CACHE:-$HOME/.cache/rrl-smb/target}"

TOOLCHAIN_CHANNEL=$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$repo/rust-toolchain.toml")
IMAGE="${RR_SMB_IMAGE:-rust:${TOOLCHAIN_CHANNEL}-bullseye}"
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "building $IMAGE from docker/toolchain.Dockerfile (once)" >&2
    docker build -f "$repo/docker/toolchain.Dockerfile" -t "$IMAGE" \
        --build-arg "RUST_TOOLCHAIN=${TOOLCHAIN_CHANNEL}" "$repo/docker" >&2
fi

# Docker creates a missing bind-mount source as root, and a run under `-u $(id -u)` then cannot
# write into it; saying so here, with the command that fixes it, is the difference between a
# five-second diagnosis and an afternoon spent reading cargo's error as a defect in the crate.
mkdir -p "$target_cache"
if [ ! -w "$target_cache" ]; then
    echo "$target_cache exists but is not writable by uid $(id -u)." >&2
    echo "  It was probably created by docker during an earlier run; fix it with:" >&2
    echo "    docker run --rm -v \"$target_cache:/x\" alpine chown -R $(id -u):$(id -g) /x" >&2
    echo "  or choose another directory: RR_SMB_TARGET_CACHE=/some/where scripts/cargo.sh ..." >&2
    exit 1
fi
case "$cargo_cache" in
/* | .*) mkdir -p "$cargo_cache" ;;
*) docker volume create "$cargo_cache" >/dev/null ;;
esac

# A sibling checkout, for building a change under test before it is pushed:
#   RR_SMB_EXTRA_MOUNT="$HOME/DevOps/3part/rrl-krb5:/sibling/rrl-krb5"
extra_mounts=""
if [ -n "${RR_SMB_EXTRA_MOUNT:-}" ]; then
    for mount in $RR_SMB_EXTRA_MOUNT; do
        extra_mounts="$extra_mounts -v $mount"
    done
fi

# The Kerberos tests talk to a KDC on the host: `scripts/test-kdc-kerberos.sh` writes
# `KRB5_TEST_KDC=127.0.0.1:<port>` into `test.env`, and `127.0.0.1` inside a container is the
# container. So when those variables are set the wrapper joins the host's network namespace and
# passes them through; without them it leaves the network alone, which is the default a build wants.
#
# Measured the other way first: a run with `test.env` sourced but no `--network host` reported
# `0 passed` on the Kerberos suites, because each file returns at its first line when the KDC
# cannot be reached - a green result that tested nothing.
krb5_env=""
network=""
for name in KRB5_TEST_REALM KRB5_TEST_KDC KRB5_TEST_KEYTAB KRB5_TEST_USER KRB5_TEST_PASSWORD \
    KRB5_TEST_SERVICE KRB5_TEST_CONFIG; do
    value=$(eval "printf '%s' \"\${$name:-}\"")
    if [ -n "$value" ]; then
        krb5_env="$krb5_env -e $name=$value"
    fi
done
if [ -n "${KRB5_TEST_KDC:-}" ]; then
    network="--network host"
fi

# `line-tables-only`: keeps the file:line a failing backtrace needs, drops what a debugger would
# show for variables. Measured on the sibling repository: 312M for a test binary at the default,
# 117M here. `RR_SMB_DEBUG=2` restores the full default, `=0` is the smallest.
debug_level="${RR_SMB_DEBUG:-line-tables-only}"

# `CARGO_INCREMENTAL=0`: with the target directory mounted from the host and the toolchain in a
# container, incremental state is rebuilt whenever anything about the mount changes.
incremental="${RR_SMB_INCREMENTAL:-0}"

# After the command, `scripts/cargo-prune.sh` removes artifacts no run has written in
# `RR_SMB_PRUNE_AGE` days (default 3) and the incremental tree. `RR_SMB_PRUNE=no` disables it for a
# run that is measuring cold-build time.
prune="${RR_SMB_PRUNE:-yes}"
prune_age="${RR_SMB_PRUNE_AGE:-3}"

# `ionice`: the build yields I/O to everything else. A flag string rather than a class, because the
# right one depends on the disk: `-c2 -n7` is best-effort at the lowest priority, `-c3` is idle and
# gets none while anything else wants the disk, which on a busy one turns a build into a stall.
# I/O priorities are applied by the block scheduler, and a device with `none` (many NVMe drives)
# ignores them; it is still set because it costs nothing and is inherited by every compiler process.
ionice_flags="${RR_SMB_IONICE:--c2 -n7}"

# `--name` so a run interrupted with ctrl-c can be found and removed: an orphan holding the target
# directory's lock blocks the next run until somebody notices.
name="smb-cargo-$$-$(date +%s)"

exec docker run --rm --name "$name" \
  -v "$repo:/w" \
  ${extra_mounts} \
  -v "$cargo_cache:/cargo" \
  -v "$target_cache:/target" \
  -w /w \
  -u "$(id -u):$(id -g)" \
  ${network} \
  -e HOME=/tmp \
  -e CARGO_HOME=/cargo \
  -e CARGO_TARGET_DIR=/target \
  -e CARGO_TERM_COLOR=never \
  -e "CARGO_INCREMENTAL=$incremental" \
  -e "CARGO_PROFILE_DEV_DEBUG=$debug_level" \
  -e "CARGO_PROFILE_TEST_DEBUG=$debug_level" \
  -e "RR_SMB_PRUNE=$prune" \
  -e "RR_SMB_PRUNE_AGE=$prune_age" \
  -e "RR_SMB_IONICE=$ionice_flags" \
  -e "MIRIFLAGS=${MIRIFLAGS:-}" \
  ${krb5_env} \
  "$IMAGE" sh -c '
    # `ionice` where it is available and permitted, the command alone where it is not: a build that
    # refuses to start because a priority could not be set would be worse than one that competes for
    # the disk.
    #
    # shellcheck disable=SC2086 # a flag string, word-split on purpose
    if ionice $RR_SMB_IONICE true 2>/dev/null; then
      set -- ionice $RR_SMB_IONICE "$@"
    fi
    "$@"
    status=$?
    # After the command, and whatever it did: a failed run has already written the artifacts of the
    # units it got through, and those are the ones that accumulate.
    case "${RR_SMB_PRUNE:-yes}" in
      no | NO | 0 | false) ;;
      *) ionice $RR_SMB_IONICE /w/scripts/cargo-prune.sh "$RR_SMB_PRUNE_AGE" >&2 || true ;;
    esac
    exit $status
  ' sh cargo "$@"
