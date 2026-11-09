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

# The toolchain version comes from rust-toolchain.toml, not from a constant here: a version written
# in two places is a version that drifts, and the drift shows up as tests that pass on one machine
# and fail on another.
#
# The base is bullseye, and it is built locally rather than pulled. `rust:<version>-bullseye` is not
# published - the official project stopped shipping bullseye variants after 1.90 - and the reason
# to want it is glibc: bullseye gives 2.31, which is what the stands and Astra Linux run, while
# bookworm gives 2.36 and a binary built there will not start. A tag assembled by hand on one
# machine is how a build starts depending on that machine, so the assembly lives in
# `docker/toolchain.Dockerfile` and is run from here when the image is absent.
channel=$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$repo/rust-toolchain.toml")
if [ -z "$channel" ]; then
    echo "rust-toolchain.toml names no channel" >&2
    exit 2
fi
image="${SMB_IMAGE:-rust:${channel}-bullseye}"
if ! docker image inspect "$image" >/dev/null 2>&1; then
    echo "building $image from docker/toolchain.Dockerfile (once)" >&2
    docker build -f "$repo/docker/toolchain.Dockerfile" \
        -t "$image" --build-arg "RUST_TOOLCHAIN=${channel}" "$repo/docker" >&2 || {
        echo "could not build $image; the mutations cannot run without it" >&2
        exit 2
    }
fi

# One cargo home for every Rust project on this machine, and it is named after the base it serves:
# a registry filled under one glibc is a registry this one may not be able to use, and the volume
# that held it says which base it was for. The volume's directories are owned by this user - a
# target or registry written by another run as root is one this run cannot write, and the failure
# reads as "Permission denied" at a path nobody typed.
#
# The build directory stays under the user's cache: it is per-checkout and large, and a shared one
# would have two runs overwrite each other's artifacts.
cache="${SMB_CACHE:-$HOME/.cache/smb-server}"
mkdir -p "$cache/target"

# Two runs in one checkout do not merely share a backup file - they share the source file. Each
# backs up what the other already mutated, and restores it afterwards, so a run can end with a
# mutation still in place and the *other* run reports a compile error or a survivor that does not
# exist. That happened: a suite that had reported 13 of 13 killed reported a survivor and a
# `could not compile` in the same batch, and neither was real.
#
# A lock, not a comment: the tool refuses rather than answers wrongly. `mkdir` is the portable
# atomic operation - `flock` is not in every image this runs in.
lock="$cache/mutate-lsarpc.lock"
if ! mkdir "$lock" 2>/dev/null; then
    echo "another mutation run holds $lock; two runs in one checkout corrupt each other" >&2
    echo "if no run is active, remove the directory by hand" >&2
    exit 2
fi

# The backup is per-run as well: the lock already excludes a second run, and a stale file from a
# run that was killed must never be the thing a later run restores.
backup="${TMPDIR:-/tmp}/lsarpc.rs.mutation-backup.$$"
trap 'rm -f "$backup"; rmdir "$lock" 2>/dev/null' EXIT INT TERM

run_tests() {
    # The output goes to a file and is read afterwards, never piped: `cargo test | tail` reports
    # `tail`'s status, so the first version of this script called every mutation a survivor - the
    # same mistake as a stand that announced a join it had not made.
    docker run --rm -u "$(id -u):$(id -g)" \
        -v "$repo":/w -w /w \
        -v "${SMB_CARGO_VOLUME:-rrl-cargo-bullseye}":/cargo -v "$cache/target":/target \
        -e CARGO_HOME=/cargo -e CARGO_TARGET_DIR=/target \
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
        # A distinct status, not a survivor: a survivor is a hole in the tests, this is a hole in
        # the script. Reporting one as the other sends the reader looking in the wrong file.
        return 2
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
stale=0
killed=0
only="${1:-}"

want() {
    [ -z "$only" ] || [ "$only" = "$1" ]
}

# Three outcomes, three counters. `check` says 0 for killed, 1 for a mutant the tests let through,
# 2 for a mutant the code has moved out from under.
record() {
    rc=0
    check "$@" || rc=$?
    case "$rc" in
    0) killed=$((killed + 1)) ;;
    1) survived=$((survived + 1)) ;;
    2) stale=$((stale + 1)) ;;
    esac
}

want order && { record "order: handle and status swapped" \
    'writer.bytes(&policy_handle());
    writer.u32(NTSTATUS_SUCCESS);' \
    'writer.u32(NTSTATUS_SUCCESS);
    writer.bytes(&policy_handle());'; }

want status && { record "status: a failure status is written instead of success" \
    'writer.u32(NTSTATUS_SUCCESS);
    writer.finish()
}

/// The same handle from the older request layout.' \
    'writer.u32(0xC000_000D);
    writer.finish()
}

/// The same handle from the older request layout.'; }

# No mutation for the discriminant's width. `u16` followed by `align(4)` writes the same four
# octets as `u32` would, so that mutation is equivalent and a survivor would say nothing about the
# tests - which is exactly what it said the first time this script ran, and cost an hour of
# looking for a hole that was not there.
want sid && { record "sid: the conformant count moves after the header" \
    'writer.u32(u32::try_from(count).unwrap_or(u32::MAX));
    writer.raw(&sid[..HEADER]);' \
    'writer.raw(&sid[..HEADER]);
    writer.u32(u32::try_from(count).unwrap_or(u32::MAX));'; }

want string && { record "string: the array's maximum equals its length" \
    'let maximum = actual.saturating_add(1);' \
    'let maximum = actual;'; }

want guid && { record "guid: the uuid is written in big-endian field order" \
    'writer.bytes(&view.guid.to_bytes_le());' \
    'writer.bytes(view.guid.as_bytes());'; }

want route && { record "route: lsa_Close reaches the open-policy answer" \
    'OPNUM_CLOSE => close_handle(stub),' \
    'OPNUM_CLOSE => open_policy(stub),'; }

want routequery && { record "route: a query reaches the close answer" \
    'OPNUM_QUERY_INFO_POLICY | OPNUM_QUERY_INFO_POLICY2 => query_info(config, stub),' \
    'OPNUM_QUERY_INFO_POLICY | OPNUM_QUERY_INFO_POLICY2 => close_handle(stub),'; }

want levelfilter && { record "level: the ushort filter accepts any level" \
    '            if levels.contains(&level) {
                return Some(level);
            }' \
    '            return Some(level);'; }

want close && { record "close: the handle is echoed back instead of nulled" \
    'writer.bytes(&[0u8; HANDLE]);' \
    'writer.bytes(&stub[..HANDLE]);'; }

# No mutation for the order of status and handle in `close_handle`. The handle is nulled and the
# status is STATUS_SUCCESS, which is zero, so both orders write twenty-four zero octets - a client
# cannot tell them apart and no test can either. An equivalent mutation is noise, and the first run
# of this script spent an hour on one.
want closeguard && { record "close: a short stub is answered" \
    'if stub.len() < HANDLE {' \
    'if false && stub.len() < HANDLE {'; }

want domainname && { record "name: the server's name wins over the domain's" \
    'netbios: match &config.domain_netbios {
                Some(name) => name.clone(),
                None => config.netbios_name.clone(),
            },' \
    'netbios: config.netbios_name.clone(),'; }

want dnsfallback && { record "dns: a stated domain is ignored" \
    'Some(domain) => domain.clone(),
        None => format!("{}.local", config.netbios_name.to_lowercase()),' \
    'Some(_) => format!("{}.local", config.netbios_name.to_lowercase()),
        None => format!("{}.local", config.netbios_name.to_lowercase()),'; }

# The offsets alone, not the `if` that follows them: the body was reformatted when the wide read
# was deleted, and a pattern spanning both lines stops applying for a reason that has nothing to do
# with the fault it describes.
want level && { record "level: only the referent offset is read" \
    'for at in [20usize, 24] {' \
    'for at in [24usize] {'; }

printf '\nkilled: %s, survivors: %s, not applied: %s\n' "$killed" "$survived" "$stale"
[ "$survived" -eq 0 ] || exit 1
[ "$stale" -eq 0 ] || {
    echo "a mutation no longer applies: the code moved, the script did not" >&2
    exit 3
}
