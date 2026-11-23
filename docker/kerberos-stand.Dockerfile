# A workbench image for the Kerberos session setup: the same compiler the gates use, plus a live
# MIT KDC.
#
# Why a second image. `SESSION_SETUP` with a Kerberos ticket cannot be reached without a KDC that
# issued the ticket: the acceptor holds a keytab, and a keytab is only useful against a ticket whose
# key came from the realm that exported it. Hand-built tickets would test the parser and not the
# handshake, and the handshake is the part no unit test can reach — `accept_kerberos` and
# `finish_kerberos` are two round trips that only exist when a client has a real ticket.
#
# bullseye, not bookworm: nothing here needs OpenSSL 3. The stand creates a realm and a keytab, which
# is all `kdb5_util` and `kadmin.local` do, and keeping the base image identical to the gates keeps
# the coverage numbers comparable with every other measurement of this crate.
FROM rust:1.99.1-bullseye

ENV DEBIAN_FRONTEND=noninteractive

# The measuring instruments come from the gates' image, where they are pinned and built: on bullseye
# the binaries match this base exactly, so no glibc question arises.
COPY --from=rust:1.99.1-bullseye /usr/local/cargo/bin/cargo-llvm-cov /usr/local/cargo/bin/cargo-llvm-cov
COPY --from=rust:1.99.1-bullseye /usr/local/cargo/bin/cargo-crap /usr/local/cargo/bin/cargo-crap

# `cargo llvm-cov` drives `llvm-cov` and `llvm-profdata` from the toolchain, which are not installed
# by default; without them the tool answers "no such command" and the failure reads like a broken
# CARGO_HOME.
RUN rustup component add llvm-tools-preview

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        krb5-kdc \
        krb5-admin-server \
        krb5-user \
        procps \
    && rm -rf /var/lib/apt/lists/*

# Checked at build time rather than assumed: without these the realm cannot be created, the test
# would skip itself, and a missing tool would look like a passing suite.
RUN command -v krb5kdc \
    && command -v kdb5_util \
    && command -v kadmin.local \
    && krb5kdc -h 2>&1 | head -1 || true

WORKDIR /w
