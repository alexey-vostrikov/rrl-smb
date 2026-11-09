#!/bin/sh
# The three ub-mode measurements, run inside the pinned image so that the compiler that builds the
# code is the compiler that measures it.
#
#   ./scripts/metrics.sh crap      # CRAP per function, from the LCOV cargo-llvm-cov writes
#   ./scripts/metrics.sh dupes     # duplicate and near-duplicate code, similarity 0.8
#   ./scripts/metrics.sh mutants   # mutation score over the whole tree
#   ./scripts/metrics.sh all       # all three, in that order
#
# CRAP needs coverage, so it is always computed first and always fresh: an LCOV older than the
# sources is an LCOV that attributes lines to the wrong functions.
set -eu

repo=$(cd "$(dirname "$0")/.." && pwd)
channel=$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$repo/rust-toolchain.toml")
if [ -z "$channel" ]; then
    echo "rust-toolchain.toml names no channel" >&2
    exit 2
fi
image="${SMB_IMAGE:-rust:${channel}-bullseye}"
if ! docker image inspect "$image" >/dev/null 2>&1; then
    echo "building $image from docker/toolchain.Dockerfile (once)" >&2
    docker build -f "$repo/docker/toolchain.Dockerfile" -t "$image" \
        --build-arg "RUST_TOOLCHAIN=${channel}" "$repo/docker" >&2
fi

cache="${SMB_CACHE:-$HOME/.cache/smb-server}"
mkdir -p "$cache/target" "$cache/coverage"

in_image() {
    docker run --rm -u "$(id -u):$(id -g)" \
        -v "$repo":/w -w /w \
        -v "${SMB_CARGO_VOLUME:-rrl-cargo-bullseye}":/cargo \
        -v "$cache/target":/target -v "$cache/coverage":/coverage \
        -e CARGO_HOME=/cargo -e CARGO_TARGET_DIR=/target \
        "$image" sh -c "$1"
}

coverage() {
    in_image 'cargo llvm-cov --lib --features krb5 --lcov \
        --output-path /coverage/lcov.info --no-cfg-coverage'
}

case "${1:-all}" in
crap)
    coverage
    in_image 'cargo crap --lcov /coverage/lcov.info --threshold 10 || true'
    ;;
dupes)
    in_image 'cargo dupes report --threshold 0.8 || true'
    ;;
mutants)
    in_image 'cargo mutants --test-command "cargo test --lib --features krb5" || true'
    ;;
all)
    coverage
    in_image 'cargo crap --lcov /coverage/lcov.info --threshold 10 || true'
    in_image 'cargo dupes report --threshold 0.8 || true'
    in_image 'cargo mutants --test-command "cargo test --lib --features krb5" || true'
    ;;
*)
    echo "unknown measurement: $1" >&2
    echo "one of: crap dupes mutants all" >&2
    exit 2
    ;;
esac
