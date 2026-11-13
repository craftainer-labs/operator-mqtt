#!/bin/sh
# Generates, into the directory given as the first argument, what the
# integration Mosquitto needs: ca.crt, server.crt and server.key (a throwaway CA
# and a server certificate for mosquitto, localhost and 127.0.0.1) and
# admin-password, the random password of the Dynamic Security admin. POSIX sh
# and openssl only, so it runs on a CI runner and in the alpine/openssl image of
# the devcontainer stack alike. Everything is valid for two days and meant to be
# thrown away.
set -eu

dir="${1:?usage: gen-certs.sh <directory>}"
mkdir -p "$dir"
cd "$dir"
umask 077

# Keep what is there while it stays valid: a running Mosquitto has loaded it,
# and a new password would no longer match the dynamic-security.json that was
# made from the old one.
if [ -s ca.crt ] && [ -s server.crt ] && [ -s server.key ] && [ -s admin-password ] &&
    openssl x509 -in server.crt -noout -checkend 3600 >/dev/null 2>&1; then
    exit 0
fi

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
    -keyout ca.key -out ca.crt -subj "/CN=operator-mqtt integration CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout server.key -out server.csr -subj "/CN=mosquitto"
cat > server.ext <<'EXT'
basicConstraints=CA:FALSE
keyUsage=digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:mosquitto,DNS:localhost,IP:127.0.0.1
EXT
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -days 2 -extfile server.ext -out server.crt
openssl rand -hex 16 > admin-password
rm -f ca.key ca.srl server.csr server.ext

# Mosquitto may run as another user than the one that generated these (it
# drops to uid 1883), and so may the test process, so everything is readable by
# all, the key too. That is acceptable for a key that lives two days in a
# directory made for one run (a CI temp directory or a compose volume nothing
# else mounts).
chmod 755 .
chmod 644 ca.crt server.crt server.key admin-password
