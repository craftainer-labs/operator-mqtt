#!/bin/sh
# Writes the Dynamic Security plugin's initial configuration, with the admin and
# its role, to the file given as the first argument, for the admin user named
# by the second and the password in the file named by the third. It runs
# inside the Mosquitto image, whose mosquitto_ctrl makes the file (the same
# role the plugin's documentation sets up: the admin may manage the plugin and
# nothing else of the tenants'). An existing file is kept: the plugin keeps
# its state there.
set -eu

file="${1:?usage: init-dynsec.sh <file> <admin-user> <password-file>}"
user="${2:?usage: init-dynsec.sh <file> <admin-user> <password-file>}"
pwfile="${3:?usage: init-dynsec.sh <file> <admin-user> <password-file>}"

if [ -s "$file" ]; then
    exit 0
fi
rm -f "$file"
# mosquitto_ctrl "dynsec init" exits non-zero by design (it suppresses the
# connection a normal command would make), so the file is what is checked.
mosquitto_ctrl dynsec init "$file" "$user" "$(cat "$pwfile")" >/dev/null || true
if [ ! -s "$file" ]; then
    echo "mosquitto_ctrl did not write $file" >&2
    exit 1
fi
