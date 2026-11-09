#!/bin/sh
# cargo-mutants over this crate, in the toolchain image the tests already run in.
#
#   ./scripts/mutants.sh                 # only the lines this branch changed against origin/main
#   ./scripts/mutants.sh --all           # the whole crate - 8212 mutants, measured in hours
#   ./scripts/mutants.sh --file src/rpc/lsarpc.rs   # 57 mutants, the practical middle
#   ./scripts/mutants.sh --list          # print what would be mutated and stop
#
# Three things make the difference between a run that answers a question and one that runs until
# somebody reboots the machine, and they are in that order of importance:
#
# 1. Scope. 8212 mutants at ~25 s each is 57 hours of wall clock. `--in-diff` reduces that to the
#    mutants inside the change under review, which is what a review actually asks about. The full
#    sweep belongs to a nightly job, not to a person.
# 2. Parallelism. `-j` is a flag and not a setting: the number of cores belongs to the machine, and
#    a committed config that says `jobs = 8` describes the laptop it was written on.
# 3. Reusing the build. A mutant is one edited file plus the whole crate rebuilt; if every mutant
#    starts from an empty target directory, the dependency graph is compiled again per mutant and
#    the wall clock is dominated by work that never changes.
#
# The curated mutations in `scripts/mutate-lsarpc.sh` are a different tool and stay as they are:
# they encode defects that actually happened here, run in about five minutes, and are cheap enough
# to be a gate. This one looks for what nobody thought of.
set -eu

repo=$(cd "$(dirname "$0")/.." && pwd)
channel=$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$repo/rust-toolchain.toml")
[ -n "$channel" ] || { echo "rust-toolchain.toml names no channel" >&2; exit 2; }
image="${SMB_IMAGE:-rust:${channel}-bullseye}"

cache="${SMB_CACHE:-$HOME/.cache/smb-server}"
mkdir -p "$cache/target"

scope=""
listing=""
mode="${MUTANTS_MODE:-copy}"

while [ $# -gt 0 ]; do
    case "$1" in
    --all) scope="--all-files" ;;
    --file) shift; scope="--file $1" ;;
    --diff) shift; scope="--in-diff ${1:-origin/main}" ;;
    --list) listing="--list" ;;
    --jobs) shift; MUTANTS_JOBS="$1" ;;
    # How each mutant's build reuses the warm target directory. `copy` copies it into the mutant's
    # own workspace (parallel-safe, costs a copy per mutant); `shared` points every build at one
    # directory through CARGO_TARGET_DIR (no copy, but cargo serialises on the directory lock, so
    # parallelism buys nothing); `none` starts cold everywhere (the slowest, kept for a fair
    # baseline rather than for use).
    --mode) shift; mode="$1" ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
done

# Default scope is the change under review. A run with no scope mutates the whole crate, which is
# the one thing a person should have to ask for explicitly.
if [ -z "$scope" ]; then
    if git -C "$repo" rev-parse --verify --quiet origin/main >/dev/null; then
        scope="--in-diff origin/main"
    else
        echo "origin/main is not known here; name a scope: --all, --file <path> or --diff <ref>" >&2
        exit 2
    fi
fi

jobs="${MUTANTS_JOBS:-$(nproc)}"

# One run at a time per checkout. cargo-mutants copies the tree per mutant, so two runs do not
# corrupt each other's sources the way `mutate-lsarpc.sh` did - but they do share the cargo
# registry and the target directory, and a shared directory with two writers is a build that fails
# once and passes on retry. That failure costs more to explain than the run costs to serialise.
lock="$cache/mutants.lock"
if ! mkdir "$lock" 2>/dev/null; then
    echo "another mutation run holds $lock; remove it by hand if no run is active" >&2
    exit 2
fi
trap 'rmdir "$lock" 2>/dev/null' EXIT INT TERM

# Docker arguments and cargo-mutants arguments are built apart: mixing them into one string and
# running it through `eval` is how a path with a space in it becomes two arguments, and how a
# quoting mistake turns into a command nobody can read.
set -- --rm -u "$(id -u):$(id -g)" -v "$repo":/w -w /w
set -- "$@" -v "${SMB_CARGO_VOLUME:-rrl-cargo-bullseye}":/cargo -e CARGO_HOME=/cargo

mutants_args=""
case "$mode" in
copy)
    set -- "$@" -v "$cache/target":/w/target
    mutants_args="--copy-target true"
    ;;
shared)
    set -- "$@" -v "$cache/target":/target -e CARGO_TARGET_DIR=/target
    mutants_args="--copy-target false"
    ;;
none)
    mutants_args="--copy-target false"
    ;;
*)
    echo "unknown mode: $mode (copy, shared, none)" >&2
    exit 2
    ;;
esac

echo "mutants: scope=$scope jobs=$jobs mode=$mode image=$image" >&2

# shellcheck disable=SC2086 # `scope` and `mutants_args` are word lists by construction, and a
# `--file` path with a space in it is not something this repository has.
docker run "$@" "$image" cargo mutants $scope $mutants_args -j "$jobs" $listing
