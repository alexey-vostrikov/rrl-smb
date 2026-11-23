#!/usr/bin/env bash
# Brings up the announcement stand and runs the tests that need it.
#
#   scripts/test-discovery-stand.sh mdns|bus|avahi [extra cargo test arguments]
#
# Three modes, because the code has three situations and they exclude each other:
#
#   mdns   no bus at all. The built-in responder takes UDP 5353 and announces — the path a machine
#          with neither D-Bus nor avahi-daemon takes.
#   bus    a system bus with no avahi-daemon on it. `Bus::connect` succeeds, the bus name has no
#          owner, and the built-in responder announces until avahi appears or the server stops.
#   avahi  a system bus with avahi-daemon on it. Registration goes through Avahi: an entry group,
#          two `AddService` calls and a `Commit`.
#
# The daemons run for the length of the script and are killed on exit. Their logs go to the terminal
# so that a stand that did not come up says why.
set -u

MODE=${1:?usage: test-discovery-stand.sh mdns|bus|avahi [test name filters]}
shift || true

cd /w || exit 1
PATH=/usr/local/cargo/bin:$PATH
export PATH

DBUS_PID=
AVAHI_PID=
cleanup() {
    [ -n "$AVAHI_PID" ] && kill "$AVAHI_PID" 2>/dev/null
    [ -n "$DBUS_PID" ] && kill "$DBUS_PID" 2>/dev/null
    return 0
}
trap cleanup EXIT

start_bus() {
    mkdir -p /run/dbus
    # `/run/dbus/system_bus_socket` is where `zbus::connection::Builder::system()` looks. The pid file
    # and the socket are removed first: a container that is reused would otherwise find a stale
    # socket and connect to a bus that is gone.
    rm -f /run/dbus/system_bus_socket /run/dbus/pid
    dbus-daemon --system --fork --print-pid > /tmp/dbus.pid || {
        echo "the system bus did not start" >&2
        exit 1
    }
    DBUS_PID=$(cat /tmp/dbus.pid)
    for _ in $(seq 1 50); do
        [ -S /run/dbus/system_bus_socket ] && return 0
        sleep 0.1
    done
    echo "the system bus socket never appeared" >&2
    exit 1
}

start_avahi() {
    mkdir -p /run/avahi-daemon
    # `--no-drop-root`: the container has no avahi user to drop to and no need for one.
    # `--no-chroot`: chrooting needs privileges the container may not have, and the daemon reads its
    # configuration from /etc either way.
    avahi-daemon --no-drop-root --no-chroot --daemonize --debug > /tmp/avahi.log 2>&1 || {
        echo "avahi-daemon did not start; its log:" >&2
        cat /tmp/avahi.log >&2
        exit 1
    }
    for _ in $(seq 1 100); do
        if avahi-browse -t _smb._tcp 2>/dev/null; then
            echo "avahi-daemon is answering"
            return 0
        fi
        sleep 0.1
    done
    echo "avahi-daemon never answered a browse; its log:" >&2
    cat /tmp/avahi.log >&2
    exit 1
}

case "$MODE" in
    mdns)
        export RRL_MDNS_STAND=1
        ;;
    bus)
        start_bus
        export RRL_DBUS_STAND=1
        ;;
    avahi)
        start_bus
        start_avahi
        AVAHI_PID=$(pgrep -f 'avahi-daemon: running' || pgrep avahi-daemon || true)
        export RRL_AVAHI_STAND=1
        ;;
    *)
        echo "unknown mode '$MODE': expected mdns, bus or avahi" >&2
        exit 2
        ;;
esac

echo "=== mode=$MODE"
# With arguments, they are the command to run under this environment — a coverage run, or one test.
# Without them, the discovery tests, which is what the stand is for.
if [ "$#" -gt 0 ]; then
    "$@"
else
    cargo test --all-features --lib discovery
fi
