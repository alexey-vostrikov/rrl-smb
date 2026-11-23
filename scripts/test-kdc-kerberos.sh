#!/usr/bin/env bash
# A throwaway MIT KDC for the Kerberos session-setup test.
#
#   scripts/test-kdc-kerberos.sh <dir> [port]
#
# Unprivileged: the realm, its database, the keytab and the logs all live in <dir>, and the KDC
# listens on <port> (default 18888, TCP and UDP), so it sits beside a system KDC without touching it.
# Needs MIT krb5's krb5kdc, kdb5_util and kadmin.local (Debian: krb5-kdc, krb5-admin-server).
#
# The realm is SMB.TEST with one user, `alice`, and one service principal,
# `cifs/samba.ad.example.com` — the name this server's SMB service is reached under, which is what a
# member's ticket names. The service's keys go to <dir>/cifs.keytab; the user's password is
# `alicepw`, fixed because nothing here protects anything.
#
# Writes <dir>/test.env with the KRB5_TEST_* variables the test reads, and leaves the daemon's
# process ID in <dir>/kdc.pid.
set -eu

DIR=${1:?usage: test-kdc-kerberos.sh <dir> [port]}
PORT=${2:-18888}
REALM=SMB.TEST
SERVICE="cifs/samba.ad.example.com"

command -v kdb5_util >/dev/null || { echo "kdb5_util is missing (Debian: krb5-kdc)" >&2; exit 1; }
command -v kadmin.local >/dev/null || { echo "kadmin.local is missing (Debian: krb5-admin-server)" >&2; exit 1; }
command -v krb5kdc >/dev/null || { echo "krb5kdc is missing (Debian: krb5-kdc)" >&2; exit 1; }

mkdir -p "$DIR"
DIR=$(cd "$DIR" && pwd)

# The KDC's own configuration, kept beside the realm so nothing is written to /etc: `KRB5_KDC_PROFILE`
# points the daemon and the admin tools at it, and every path in it is under $DIR.
cat > "$DIR/kdc.conf" <<EOF
[kdcdefaults]
 kdc_ports = $PORT
 kdc_tcp_ports = $PORT

[realms]
 $REALM = {
  database_name = $DIR/principal
  key_stash_file = $DIR/.k5.$REALM
  acl_file = $DIR/kadm5.acl
  admin_keytab = $DIR/kadm5.keytab
  max_life = 10h
  max_renewable_life = 7d
  supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal aes256-cts-hmac-sha384-192:normal aes128-cts-hmac-sha256-128:normal
 }
EOF
echo "*/admin@$REALM *" > "$DIR/kadm5.acl"

# What a client needs to find the realm: the same file `kinit` and this crate's `KdcClient` read.
cat > "$DIR/krb5.conf" <<EOF
[libdefaults]
 default_realm = $REALM
 dns_lookup_kdc = false
 dns_lookup_realm = false
 udp_preference_limit = 1

[realms]
 $REALM = {
  kdc = 127.0.0.1:$PORT
  admin_server = 127.0.0.1:$PORT
 }

[domain_realm]
 .ad.example.com = $REALM
 ad.example.com = $REALM
EOF

export KRB5_KDC_PROFILE="$DIR/kdc.conf"
export KRB5_CONFIG="$DIR/krb5.conf"

if [ ! -f "$DIR/principal" ]; then
    kdb5_util create -s -r "$REALM" -P masterpw >/dev/null
fi

# The principal `kadmin.local` names itself when it runs a query.
#
# Without `-p` it derives the name from the current user through `getpwuid`, and in a container the
# process is a bare uid with no passwd entry: every query then fails with "unable to figure out a
# principal name", which reads like a broken realm rather than a missing line in `/etc/passwd`.
KADMIN="admin/admin@$REALM"

# One admin query, with the failure made visible.
#
# `kadmin.local` exits 0 even when the query failed, so the output is what says whether it worked; the
# greeting it prints on success is dropped so that a caller comparing against empty output does not
# read it as an error.
kadmin_query() {
    out=$(kadmin.local -r "$REALM" -p "$KADMIN" -q "$*" 2>&1 | sed -e '/^Authenticating as /d')
    if grep -qiE 'error|cannot|failed|usage' <<<"$out"; then
        echo "kadmin.local -q '$*' failed:" >&2
        echo "$out" >&2
        exit 1
    fi
}

# The principals the test needs. `addprinc` on an existing principal is an error, so each is created
# only when it is missing — the script then runs on a directory that already holds a realm.
add_principal() {
    if ! kadmin.local -r "$REALM" -p "$KADMIN" -q "getprinc $1" 2>&1 | grep -q "^Principal:"; then
        kadmin_query "addprinc $2 $1"
    fi
}
add_principal "alice@$REALM" "-pw alicepw"
add_principal "$SERVICE@$REALM" "-randkey"

# The service's keys, which is what the server's acceptor holds. Re-extracted every run so the
# keytab and the database cannot drift apart.
rm -f "$DIR/cifs.keytab"
kadmin_query "ktadd -k $DIR/cifs.keytab $SERVICE@$REALM"
test -s "$DIR/cifs.keytab" || { echo "the keytab was not written" >&2; exit 1; }

if [ -f "$DIR/kdc.pid" ] && kill -0 "$(cat "$DIR/kdc.pid")" 2>/dev/null; then
    kill "$(cat "$DIR/kdc.pid")" 2>/dev/null || true
    sleep 1
fi
krb5kdc -r "$REALM" -P "$DIR/kdc.pid" -n > "$DIR/kdc.log" 2>&1 &
sleep 1

# A live check rather than "the daemon was started": until the KDC answers, a test that connects to
# it fails with a timeout, which reads as a bug in the code under test.
if ! kadmin.local -r "$REALM" -p "$KADMIN" -q "listprincs" >/dev/null 2>&1; then
    echo "the KDC does not answer; its log:" >&2
    cat "$DIR/kdc.log" >&2
    exit 1
fi

cat > "$DIR/test.env" <<EOF
KRB5_TEST_REALM=$REALM
KRB5_TEST_KDC=127.0.0.1:$PORT
KRB5_TEST_KEYTAB=$DIR/cifs.keytab
KRB5_TEST_USER=alice
KRB5_TEST_PASSWORD=alicepw
KRB5_TEST_SERVICE=$SERVICE
KRB5_TEST_CONFIG=$DIR/krb5.conf
EOF

echo "KDC for $REALM on $PORT, keytab in $DIR/cifs.keytab, env in $DIR/test.env"
