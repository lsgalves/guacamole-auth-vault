#!/bin/bash
#
# Starts xrdp (session manager + listener) in the foreground.
#
set -e

# Clear any stale pid files from a previous run.
rm -f /var/run/xrdp/*.pid 2>/dev/null || true

# The XFCE session needs a system D-Bus.
mkdir -p /run/dbus
dbus-daemon --system --fork 2>/dev/null || true

# Session manager (daemonizes), then the RDP listener in the foreground.
/usr/sbin/xrdp-sesman
exec /usr/sbin/xrdp --nodaemon
