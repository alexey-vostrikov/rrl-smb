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
image="${SMB_IMAGE:-rust:1.99.1-slim-trixie}"
backup="${TMPDIR:-/tmp}/lsarpc.rs.mutation-backup"

run_tests() {
    docker run --rm -v "$repo":/w -w /w -v rrl-cargo:/cargo -e CARGO_HOME=/cargo \
        "$image" sh -c 'cargo test --lib --features krb5 lsarpc 2>&1 | tail -5'
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
    printf '%s ... ' "$name"
    if ! apply "$old" "$new" 2>/dev/null; then
        printf 'NOT APPLIED (the code moved)\n'
        cp "$backup" "$file"
        return 1
    fi
    if run_tests >/tmp/mutation.log 2>&1; then
        printf 'SURVIVED\n'
        result=0
    else
        printf 'killed\n'
        result=1
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

want referent && { check "referent: the handle pointer is not written" \
    '    writer.pointer(true);
    writer.bytes(&policy_handle());' \
    '    writer.bytes(&policy_handle());' || survived=$((survived + 1)); }

want discriminant && { check "discriminant: the union tag is written as a word" \
    'writer.u16(level);' \
    'writer.u32(u32::from(level));' || survived=$((survived + 1)); }

want sid && { check "sid: the conformant count moves after the header" \
    'writer.u32(u32::try_from(count).unwrap_or(u32::MAX));
    writer.raw(&sid[..HEADER]);' \
    'writer.raw(&sid[..HEADER]);
    writer.u32(u32::try_from(count).unwrap_or(u32::MAX));' || survived=$((survived + 1)); }

want level && { check "level: only the referent offset is read" \
    'for at in [20usize, 24] {
        if let Some(bytes) = stub.get(at..at + 2)' \
    'for at in [24usize] {
        if let Some(bytes) = stub.get(at..at + 2)' || survived=$((survived + 1)); }

printf '\nsurvivors: %s\n' "$survived"
[ "$survived" -eq 0 ]
