vault_addr      = "http://vault:8200"
ssh_mount_point = "ssh"
allowed_roles   = "*"

# This lab runs Vault over plain HTTP; skip TLS verification. Use TLS and a
# proper CA in production.
tls_skip_verify = true
