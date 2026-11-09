#!/bin/sh
# Mutations for the lsarpc module: each one changes the wire in a way that a real client would
# notice, and the question is whether any test notices first.
#
# Why these five and not a generator's five hundred: every one of them is a fault that actually
# happened here. A mutation that kills nothing is either a hole in the tests or a change no client
# can see, and the difference is worth knowing - `cargo-mutants` generates the second kind by the
# hundred and buries the first.
#
#   ./scripts/mutate-lsarpc.sh          # every mutation
#   ./scripts/mutate-lsarpc.sh order    # one, by name
#
# Each run: apply, run the module's tests, revert. A mutation is killed when the tests fail and
# survives when they pass - a surviving mutation is a test that would have let the fault through.
set -eu

repo=$(cd "$(dirname "$0")/.." && pwd)
file="$repo/src/rpc/lsarpc.rs"

# The image tag comes from rust-toolchain.toml, not from a constant here: a version written in two
# places is a version that drifts, and the drift shows up as tests that pass on one machine and
# fail on another. `SMB_IMAGE` overrides it for a one-off run against another toolchain.
channel=$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$repo/rust-toolchain.toml")
if [ -z "$channel" ]; then
    echo "rust-toolchain.toml names no channel" >&2
    exit 2
fi
image="${SMB_IMAGE:-rust:${channel}-slim-trixie}"
backup="${TMPDIR:-/tmp}/lsarpc.rs.mutation-backup"

run_tests() {
    # The output goes to a file and is read afterwards, never piped: `cargo test | tail` reports
    # `tail`'s status, so the first version of this script called every mutation a survivor - the
    # same mistake as a stand that announced a join it had not made.
    docker run --rm -v "$repo":/w -w /w -v rrl-cargo:/cargo -e CARGO_HOME=/cargo \
        "$image" sh -c 'cargo test --lib --features krb5 lsarpc >/tmp/mutation.log 2>&1'
    status=$?
    tail -5 /tmp/mutation.log 2>/dev/null || true
    return $status
}

# Applies one mutation by replacing text, and fails loudly if the text is not there: a mutation
# that silently applies nothing reports a survivor that was never mutated.
apply() {
    old=$1
    new=$2
    python3 - "$file" "$old" "$new" <<'PY'
import sys

path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(path, encoding="utf-8").read()
if old not in text:
    sys.exit(f"mutation does not apply: {old!r} not found")
open(path, "w", encoding="utf-8").write(text.replace(old, new, 1))
PY
}

check() {
    name=$1
    old=$2
    new=$3
    cp "$file" "$backup"
    printf '\n%s ... ' "$name"
    if ! apply "$old" "$new" 2>/dev/null; then
        printf 'NOT APPLIED (the code moved)\n'
        cp "$backup" "$file"
        return 1
    fi
    if run_tests; then
        printf 'SURVIVED\n'
        result=1
    else
        printf 'killed\n'
        result=0
    fi
    cp "$backup" "$file"
    return $result
}

survived=0
only="${1:-}"

want() {
    [ -z "$only" ] || [ "$only" = "$1" ]
}

want order && { check "order: handle and status swapped" \
    'writer.bytes(&policy_handle());
    writer.u32(NTSTATUS_SUCCESS);' \
    'writer.u32(NTSTATUS_SUCCESS);
    writer.bytes(&policy_handle());' || survived=$((survived + 1)); }

want status && { check "status: a failure status is written instead of success" \
    'writer.u32(NTSTATUS_SUCCESS);
    writer.finish()
}

/// The same handle from the older request layout.' \
    'writer.u32(0xC000_000D);
    writer.finish()
}

/// The same handle from the older request layout.' || survived=$((survived + 1)); }

# No mutation for the discriminant's width. `u16` followed by `align(4)` writes the same four
# octets as `u32` would, so that mutation is equivalent and a survivor would say nothing about the
# tests - which is exactly what it said the first time this script ran, and cost an hour of
# looking for a hole that was not there.
want sid && { check "sid: the conformant count moves after the header" \
    'writer.u32(u32::try_from(count).unwrap_or(u32::MAX));
    writer.raw(&sid[..HEADER]);' \
    'writer.raw(&sid[..HEADER]);
    writer.u32(u32::try_from(count).unwrap_or(u32::MAX));' || survived=$((survived + 1)); }

want string && { check "string: the array's maximum equals its length" \
    'let maximum = actual.saturating_add(1);' \
    'let maximum = actual;' || survived=$((survived + 1)); }

want guid && { check "guid: the uuid is written in big-endian field order" \
    'writer.bytes(&view.guid.to_bytes_le());' \
    'writer.bytes(view.guid.as_bytes());' || survived=$((survived + 1)); }

want level && { check "level: only the referent offset is read" \
    'for at in [20usize, 24] {
        if let Some(bytes) = stub.get(at..at + 2)' \
    'for at in [24usize] {
        if let Some(bytes) = stub.get(at..at + 2)' || survived=$((survived + 1)); }

printf '\nsurvivors: %s\n' "$survived"
[ "$survived" -eq 0 ]
