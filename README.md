# Guacamole + HashiCorp Vault SSH OTP

A custom Apache Guacamole extension (Java) that, **when you open a connection**,
fetches its password from **HashiCorp Vault** and injects it into the connection's
`password` parameter. The source depends on the protocol:

- **SSH** → a one-time password from Vault's **SSH secrets engine** (*OTP* mode).
- **RDP** → a static password from Vault's **KV secrets engine**, at a path
  derived from the protocol and connection name.

In both cases the extension only acts when the connection's `password` is set to
the trigger token `${VAULT_SECRET}` (configurable).

Guacamole itself uses its **normal database backend** (`guacamole-auth-jdbc-mysql`
on MariaDB): you log into the regular multi-user UI, manage connections/users,
and the Vault extension only kicks in *when a connection is actually opened*. A
full `docker compose` lab is included: MariaDB, Vault, an RDP target (xrdp), a
Linux SSH target running
`vault-ssh-helper`, `guacd`, and the Guacamole web app with the extension baked in.

```
Browser ──► Guacamole (extension) ──┐
                │  1. protocol == ssh?                  4. SSH login with OTP
                │  2. resolve host ──► IP               ┌──────────────────────┐
                ▼  3. POST ssh/creds/<role>             ▼                      │
            HashiCorp Vault ◄───────────────────── ssh-host (sshd + PAM)       │
                ▲   5. ssh/verify(OTP) ──────────────── vault-ssh-helper ──────┘
                └──────────────────────────────────────────────┘
            guacd ──► opens the SSH session using the injected ${VAULT_SECRET}
```

## How it works

1. The extension is purely a **decorator** — it has no users of its own. After
   you authenticate (against the MySQL/JDBC backend, LDAP, SSO, …), its
   `VaultAuthenticationProvider.decorate()` wraps whatever `UserContext` that
   backend produced in a `TokenInjectingUserContext` (`VaultUserContext`). So it
   composes with `guacamole-auth-jdbc-mysql` without any special wiring.
2. **Only at connect time**, `getTokens(Connection)` runs. It reads the
   connection parameters (via the *privileged* connection directory, since JDBC
   masks parameter values from non-administrators) and acts **only if** the
   `password` references the trigger token `${VAULT_SECRET}`. Then it branches by
   protocol:
   - **`ssh`** → resolves the `hostname` to an IP (Vault OTPs are bound to an IP)
     and calls `POST /v1/ssh/creds/<role>`, returning the one-time password.
   - **`rdp`** → reads `GET /v1/<kv-mount>/data/<prefix>/rdp/<connection-name>`
     (KV v2) and returns the secret's `password` field.
   - any other protocol → left untouched.
3. The returned value is placed in the `${VAULT_SECRET}` token, so Guacamole
   substitutes it into the `password` parameter and hands it to `guacd`.
4. For SSH, `guacd` opens the session (keyboard-interactive); on the target,
   `sshd` → PAM → `vault-ssh-helper` validates the single-use OTP against Vault.
   For RDP, `guacd` authenticates with the static password from the KV.

### Vault KV path convention (RDP)

RDP passwords are looked up at a predictable path built from the protocol and the
**connection name**:

```
<kv-mount>/<kv-prefix>/<protocol>/<connection-name>
        e.g.  secret/guacamole/rdp/rdp-host
```

Store the secret with a `password` field (the connection-name path segment is
URL-encoded, so names with spaces work):

```bash
vault kv put secret/guacamole/rdp/rdp-host \
    username=rdpuser password='RdpExampleP@ssw0rd'
```

An RDP connection **named `rdp-host`** with its `password` set to
`${VAULT_SECRET}` then resolves to this secret. (Mount/prefix/version/field are
all configurable — see the properties table.) The lab seeds exactly this secret,
the matching connection, and an `xrdp` host with a `rdpuser` whose password is
the same value — so it works end to end out of the box.

Each SSH connection consumes one freshly minted OTP; RDP reads the current KV value.

## Repository layout

```
.
├── pom.xml                              # Maven build for the extension
├── src/main/java/com/lsgalves/guacamole/auth/vault/
│   ├── VaultAuthenticationProvider.java # decorate() hook
│   ├── VaultUserContext.java            # SSH detection + token injection
│   ├── client/VaultClient.java          # Vault HTTP client: AppRole, SSH OTP, KV (Java 8)
│   ├── client/VaultTokenProvider.java   # AppRole token cache + re-login
│   └── conf/                            # guacamole.properties handling
├── src/main/resources/guac-manifest.json
├── compose.yml
└── deploy/
    ├── guacamole/                       # Dockerfile (multi-stage), guacamole.properties
    ├── database/initdb/                 # Guacamole MySQL schema + seeded demo connection
    ├── ssh-host/                        # Dockerfile, sshd_config, PAM, vault-ssh-helper.hcl
    ├── rdp-host/                        # Dockerfile (xrdp + XFCE), entrypoint, startwm.sh
    └── vault/bootstrap.sh               # SSH engine, OTP role, policy, AppRole credentials
```

## Quick start

Requirements: Docker + Docker Compose. (No local Java/Maven needed — the
extension is built inside the Guacamole image.)

```bash
docker compose up -d --build
```

Then open **http://localhost:8080/guacamole** and log in:

| Field    | Value       |
|----------|-------------|
| Username | `guacadmin` |
| Password | `guacadmin` |

You land on the **normal Guacamole home screen**. The lab pre-seeds two
connections (create your own the same way from *Settings → Connections* — just
leave the password as `${VAULT_SECRET}`):

- **“ssh-host (Vault SSH OTP)”** — clicking it makes Guacamole fetch a one-time
  password from Vault's SSH engine and log you into the SSH terminal.
- **“rdp-host”** — clicking it makes Guacamole read the password from Vault's KV
  engine and open the XFCE desktop over RDP.

Either way you never type or store the target password.

Tear down (and wipe the database + dev Vault state) with:

```bash
docker compose down -v
```

## Services

| Service           | Description                                                        | Port (host) |
|-------------------|--------------------------------------------------------------------|-------------|
| `database`        | MariaDB; auto-applies the Guacamole schema + seeds a demo connection| –          |
| `vault`           | HashiCorp Vault in **dev mode** (root token `root`)                | 8200        |
| `vault-bootstrap` | One-shot: SSH engine, OTP role, policy and AppRole credentials     | –           |
| `ssh-host`        | Ubuntu + `sshd` + `vault-ssh-helper`, user `guacuser`              | 2222 → 22   |
| `rdp-host`        | Ubuntu + `xrdp` + XFCE desktop, user `rdpuser`                     | 3389 → 3389 |
| `guacd`           | Guacamole proxy daemon                                             | –           |
| `guacamole`       | Web app with `guacamole-auth-jdbc-mysql` + the Vault extension     | 8080        |

## Extension configuration (`guacamole.properties`)

| Property                | Required | Default        | Description                                            |
|-------------------------|----------|----------------|--------------------------------------------------------|
| `vault-addr`            | yes      | –              | Vault base URL, e.g. `http://vault:8200`               |
| `vault-approle-role-id` | one of\* | –              | AppRole role ID (enables AppRole login)                |
| `vault-approle-role-id-file` | one of\* | –         | Path to a file holding the AppRole role ID             |
| `vault-approle-secret-id` | no\*\*\* | –            | AppRole secret ID                                      |
| `vault-approle-secret-id-file` | no\*\*\* | –       | Path to a file holding the secret ID (read per login)  |
| `vault-approle-mount`   | no       | `approle`      | AppRole auth method mount point                        |
| `vault-token`           | one of\* | –              | Inline static Vault token (used if AppRole isn't set)  |
| `vault-token-file`      | one of\* | –              | Path to a file holding the static token (read per-call)|
| `vault-ssh-mount`       | no       | `ssh`          | SSH secrets engine mount point                         |
| `vault-ssh-role`        | yes\*\*  | –              | OTP role name (required if you use SSH connections)    |
| `vault-secret-token-name`  | no       | `VAULT_SECRET`| Parameter token that triggers the extension and is populated with the secret |
| `vault-kv-mount`        | no       | `secret`       | KV secrets engine mount point (used for RDP)           |
| `vault-kv-version`      | no       | `2`            | KV engine version (`1` or `2`)                         |
| `vault-kv-prefix`       | no       | `guacamole`    | Path prefix under the KV mount                         |
| `vault-kv-password-field`| no      | `password`     | Field within the KV secret holding the password        |

\*\* Only required if you actually use SSH connections.

\* Configure either AppRole (a role ID, inline or from a file) or a static token
(`vault-token` / `vault-token-file`). If a role ID is set, AppRole is used and
the static token is ignored.

\*\*\* Required unless the AppRole role has `bind_secret_id=false`.

**AppRole (recommended; used by the lab).** The extension logs in on the first
Vault call, caches the short-lived token it gets back and shares it across all
users, then logs in again once 80% of the token's TTL has elapsed. If Vault
answers `403` (e.g. the token was revoked), it logs in again and retries once.
Logins happen on demand, so nothing needs to be renewed in the background, and a
Guacamole that was down for longer than the token TTL just logs in again. The lab's
`vault-bootstrap` service creates the role and writes the role ID and a secret
ID to a shared volume at `/vault-shared/guac.role-id` and
`/vault-shared/guac.secret-id`.

**Static token.** Used as-is and never renewed, so it must outlive Guacamole's
uptime (or be rotated externally; `vault-token-file` is re-read on every call).

## Building

This is only needed if you want to install the extension on an existing
Guacamole instance. (The `docker compose` lab already builds the jar inside the
Guacamole image, so you don't need a local toolchain for the quick start.)

**Requirements**

- JDK 11 or newer (the build compiles to Java 8 bytecode via `--release 8`).
- Maven 3.6+.

**Build**

```bash
mvn clean package
```

The shaded, ready-to-deploy jar is written to:

```
target/guacamole-auth-vault-ssh-otp-1.1.0.jar
```

> The jar targets **Java 8** to match the runtime of the official
> `guacamole/guacamole:1.5.5` image. Jackson is shaded and relocated into the
> extension's own package so it cannot clash with the web app's own copy.

Without a local JDK/Maven you can build the jar entirely in a container:

```bash
docker run --rm -v "$PWD":/build -w /build maven:3.9-eclipse-temurin-17 \
    mvn -q clean package
```

## Installing the jar in Apache Guacamole

Guacamole loads extensions from the `extensions/` subdirectory of its
configuration home, `GUACAMOLE_HOME` (commonly `/etc/guacamole`, or
`~/.guacamole` for the user running the servlet container).

1. **Copy the jar into the extensions directory:**

   ```bash
   mkdir -p /etc/guacamole/extensions
   cp target/guacamole-auth-vault-ssh-otp-1.1.0.jar /etc/guacamole/extensions/
   ```

2. **Configure the extension** in `/etc/guacamole/guacamole.properties` (see the
   table above for all properties):

   ```properties
   vault-addr:                   https://vault.example.com:8200
   vault-approle-role-id:        <role-id>
   vault-approle-secret-id-file: /etc/guacamole/vault-secret-id
   vault-ssh-mount: ssh
   vault-ssh-role:  otp_key_role
   ```

3. **Restart the servlet container** (e.g. `systemctl restart tomcat9`) so
   Guacamole reloads its extensions.

4. **Verify** it loaded — the Guacamole/Tomcat log should show:

   ```
   Extension "Vault SSH OTP" (vault-ssh-otp) loaded.
   ```

5. **Use it:** on any SSH connection, set the `password` parameter to
   `${VAULT_SECRET}`. The OTP is fetched from Vault and injected only when that
   connection is opened. (Each target host must run `vault-ssh-helper`, and the
   OTP role's `cidr_list` must cover it.)

### Installing into the official Docker image

The official `guacamole/guacamole` image rebuilds `GUACAMOLE_HOME` on every
start, so bind-mounting a jar into it directly does not survive. Instead, point
the image at a *template* home it copies on startup (this is exactly what this
lab's `deploy/guacamole/Dockerfile` does):

```yaml
services:
  guacamole:
    image: guacamole/guacamole:1.5.5
    environment:
      GUACAMOLE_HOME: /guac-home      # used as the template; copied on startup
      # ... your MYSQL_*/GUACD_* variables ...
    volumes:
      - ./guac-home:/guac-home:ro     # contains extensions/<jar> + guacamole.properties
```

Place the jar at `./guac-home/extensions/guacamole-auth-vault-ssh-otp-1.1.0.jar`
and your settings at `./guac-home/guacamole.properties`.

## Vault setup performed by the bootstrap

```hcl
# SSH OTP role
key_type     = "otp"
default_user = "guacuser"
cidr_list    = "0.0.0.0/0"      # lab only — restrict in production

# Example RDP secret (KV v2, mounted at secret/ by default in dev mode)
#   secret/guacamole/rdp/rdp-host  ->  { username, password }

# SSH mount tuning: unused OTPs expire after 2 minutes
default_lease_ttl = "2m"
max_lease_ttl     = "2m"

# Guacamole policy (least privilege): mint SSH OTPs + read connection secrets
path "ssh/creds/otp_key_role"   { capabilities = ["create", "update"] }
path "secret/data/guacamole/*"  { capabilities = ["read"] }

# AppRole auth/approle/role/guacamole
token_policies        = "guac-secrets"
token_ttl             = "1h"
token_max_ttl         = "1h"
secret_id_ttl         = 0               # lab only — expire and rotate in production
secret_id_bound_cidrs = "<guacnet subnet>"
token_bound_cidrs     = "<guacnet subnet>"
```

The secret ID can only be used, and the resulting tokens are only accepted,
from the Docker network shared by Guacamole and Vault (detected by the bootstrap).

## Verifying manually

Log in with the same AppRole the extension uses. The role is bound to the lab's
Docker network, so the CLI inside the `vault` container must talk to
`http://vault:8200` (not its default `127.0.0.1`) for the request to come from
an allowed address:

```bash
ROLE_ID=$(docker compose exec -T guacamole cat /vault-shared/guac.role-id)
SECRET_ID=$(docker compose exec -T guacamole cat /vault-shared/guac.secret-id)
TOKEN=$(docker compose exec -T -e VAULT_ADDR=http://vault:8200 vault \
  vault write -field=token auth/approle/login role_id="$ROLE_ID" secret_id="$SECRET_ID")
```

Generate an OTP with that token and log in by hand:

```bash
IP=$(docker compose exec -T ssh-host getent hosts ssh-host | awk '{print $1}')

OTP=$(docker compose exec -T -e VAULT_ADDR=http://vault:8200 -e VAULT_TOKEN="$TOKEN" vault \
  vault write -field=key ssh/creds/otp_key_role ip=$IP username=guacuser)

# from any container on the network:
sshpass -p "$OTP" ssh -o PreferredAuthentications=keyboard-interactive guacuser@ssh-host hostname
```

Read the RDP password from the KV with the same token (the path the extension
builds for a connection named `rdp-host`):

```bash
docker compose exec -T -e VAULT_ADDR=http://vault:8200 -e VAULT_TOKEN="$TOKEN" vault \
  vault kv get -mount=secret guacamole/rdp/rdp-host
```

Useful logs:

```bash
docker compose logs guacamole          # "Extension \"Vault SSH OTP\" ... loaded."
docker compose logs vault-bootstrap    # Vault configuration
docker compose exec ssh-host cat /var/log/vault-ssh-helper.log
```

## Production notes

This lab favours simplicity. Before using anything like it for real:

- Run Vault with **TLS** (not dev mode), and remove the `-dev` flag from the
  `vault-ssh-helper` PAM line in `deploy/ssh-host/pam_sshd`.
- Give the AppRole secret ID a TTL (`secret_id_ttl`) and rotate it, or deliver
  it with response wrapping, and bind it to the Guacamole hosts' addresses.
  Tighten the OTP role's `cidr_list`.
- Change the default `guacadmin` password and the MariaDB credentials, and don't
  commit the seeded connection. The extension works alongside any auth backend
  (JDBC/LDAP/SSO), so swap the database for whatever you already use.
