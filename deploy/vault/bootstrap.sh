#!/bin/sh
#
# Configures Vault's SSH secrets engine (OTP mode) and KV secrets engine (for
# RDP/static passwords), and provisions AppRole credentials for the Guacamole
# extension.
# Idempotent: safe to re-run.
#
set -eu

# Path prefix under the KV mount that the extension reads (matches
# vault-kv-prefix in guacamole.properties): <prefix>/<protocol>/<connection-name>
KV_PREFIX=guacamole

echo "[bootstrap] Waiting for Vault to be ready at ${VAULT_ADDR} ..."
until vault status >/dev/null 2>&1; do
    sleep 2
done
echo "[bootstrap] Vault is ready."

# Enable the SSH secrets engine at the 'ssh' mount (ignore if already enabled).
if vault secrets list -format=json | grep -q '"ssh/"'; then
    echo "[bootstrap] SSH secrets engine already enabled."
else
    echo "[bootstrap] Enabling SSH secrets engine at ssh/ ..."
    vault secrets enable -path=ssh ssh
fi

# Cap the lifetime of unused OTPs. The role's 'ttl' is ignored for key_type=otp,
# so the lease TTL must be set on the mount. The extension requests the OTP right
# before connecting, so a couple of minutes is plenty; once the lease expires,
# Vault revokes (deletes) the OTP.
echo "[bootstrap] Limiting SSH OTP lease TTL to 2m ..."
vault secrets tune -default-lease-ttl=2m -max-lease-ttl=2m ssh/

# Create / update the OTP role. cidr_list is wide open for this lab; restrict it
# in production to the network of the hosts you intend to reach.
echo "[bootstrap] Writing OTP role 'otp_key_role' ..."
vault write ssh/roles/otp_key_role \
    key_type=otp \
    default_user=guacuser \
    cidr_list=0.0.0.0/0

# Seed an example RDP secret so the KV path convention is demonstrable. The KV
# v2 engine is mounted at 'secret/' by default in Vault dev mode. The path is
# <prefix>/<protocol>/<connection-name>; here the connection is named "rdp-host".
echo "[bootstrap] Seeding example RDP secret in KV ..."
vault kv put "secret/${KV_PREFIX}/rdp/rdp-host" \
    username=rdpuser \
    password='RdpExampleP@ssw0rd'

# Least-privilege policy: generate SSH OTPs, and read connection secrets from KV.
# (KV v2 reads go through the 'data/' path.)
echo "[bootstrap] Writing policy 'guac-secrets' ..."
vault policy write guac-secrets - <<EOF
path "ssh/creds/otp_key_role" {
  capabilities = ["create", "update"]
}

path "secret/data/${KV_PREFIX}/*" {
  capabilities = ["read"]
}
EOF

# Enable the AppRole auth method (ignore if already enabled).
if vault auth list -format=json | grep -q '"approle/"'; then
    echo "[bootstrap] AppRole auth method already enabled."
else
    echo "[bootstrap] Enabling AppRole auth method at approle/ ..."
    vault auth enable approle
fi

# Only the Docker network shared by Guacamole and Vault may log in with the
# secret ID or use the tokens it yields. This container sits on that network, so
# its on-link route is the subnet.
GUAC_CIDR=$(ip -o -f inet route show dev eth0 scope link | awk '{print $1; exit}')
if [ -z "${GUAC_CIDR}" ]; then
    echo "[bootstrap] Unable to determine the Docker network subnet." >&2
    exit 1
fi

# AppRole for Guacamole: it logs in on demand and gets short-lived tokens
# (token_ttl), logging in again as they expire. The secret ID never expires
# (secret_id_ttl=0) so the lab keeps working; in production give it a TTL and
# rotate it, or deliver it with response wrapping.
echo "[bootstrap] Writing AppRole 'guacamole' (bound to ${GUAC_CIDR}) ..."
vault write auth/approle/role/guacamole \
    token_policies=guac-secrets \
    token_ttl=1h \
    token_max_ttl=1h \
    secret_id_ttl=0 \
    secret_id_bound_cidrs="${GUAC_CIDR}" \
    token_bound_cidrs="${GUAC_CIDR}"

# Hand the role ID and a fresh secret ID to Guacamole via the shared volume. It
# reads them through the 'vault-approle-role-id-file' and
# 'vault-approle-secret-id-file' properties.
echo "[bootstrap] Issuing Guacamole AppRole credentials ..."
vault read -field=role_id auth/approle/role/guacamole/role-id > /vault-shared/guac.role-id
vault write -f -field=secret_id auth/approle/role/guacamole/secret-id > /vault-shared/guac.secret-id
chmod 644 /vault-shared/guac.role-id /vault-shared/guac.secret-id

echo "[bootstrap] Done. AppRole credentials written to /vault-shared/guac.{role-id,secret-id}"
