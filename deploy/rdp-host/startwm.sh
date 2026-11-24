#!/bin/sh
#
# Window-manager startup for xrdp sessions: launch XFCE.
#
if [ -r /etc/profile ]; then
    . /etc/profile
fi

exec startxfce4
