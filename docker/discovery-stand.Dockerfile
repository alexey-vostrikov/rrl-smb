# A workbench image for the two announcement backends: the compiler the gates use, plus a D-Bus
# system bus and avahi-daemon.
#
# Why a second image. `discovery/avahi.rs` talks to avahi-daemon over the system bus, and
# `discovery/responder.rs` binds UDP 5353 — neither statement can be made in a process with no bus and
# no port. A mock bus would test the mock: the interesting part is that `EntryGroupNew` answers with an
# object path, that `AddService` takes nine arguments in the order Avahi declares them, and that a
# name already taken comes back as a D-Bus *error* rather than as a reply.
#
# What it does not do is run as the user: avahi's D-Bus policy lets only root own
# `org.freedesktop.Avahi`, so the container runs as root and writes to its own target directory
# (`/target`, its own volume), never to a tree the user's runs also use.
FROM rust:1.99.1-bullseye

ENV DEBIAN_FRONTEND=noninteractive

RUN rustup component add llvm-tools-preview

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        dbus \
        avahi-daemon \
        avahi-utils \
        procps \
    && rm -rf /var/lib/apt/lists/*

# Checked at build time rather than assumed: without these the stand cannot start, every stand test
# would skip itself, and a missing daemon would look like a passing suite.
RUN command -v dbus-daemon \
    && command -v avahi-daemon \
    && command -v avahi-browse \
    && test -f /usr/share/dbus-1/system.conf

WORKDIR /w
