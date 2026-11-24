package com.lsgalves.guacamole.auth.vault.conf;

import org.apache.guacamole.properties.IntegerGuacamoleProperty;
import org.apache.guacamole.properties.StringGuacamoleProperty;

/**
 * Properties read from guacamole.properties that configure how this extension
 * talks to HashiCorp Vault.
 */
public final class VaultProperties {

    private VaultProperties() {}

    /**
     * The base URL of the Vault server, e.g. "http://vault:8200". Required.
     */
    public static final StringGuacamoleProperty VAULT_ADDR =
            new StringGuacamoleProperty() {
                @Override
                public String getName() { return "vault-addr"; }
            };

    /**
     * A static Vault token used by this extension to request secrets. Used only
     * when AppRole is not configured (see {@link #VAULT_APPROLE_ROLE_ID}); then
     * either this or {@link #VAULT_TOKEN_FILE} must be provided.
     */
    public static final StringGuacamoleProperty VAULT_TOKEN =
            new StringGuacamoleProperty() {
                @Override
                public String getName() { return "vault-token"; }
            };

    /**
     * Path to a file whose contents are the Vault token. Useful when the token
     * is provisioned at runtime (e.g. written to a shared volume). Takes effect
     * only when {@link #VAULT_TOKEN} is not set.
     */
    public static final StringGuacamoleProperty VAULT_TOKEN_FILE =
            new StringGuacamoleProperty() {
                @Override
                public String getName() { return "vault-token-file"; }
            };

    /**
     * The mount point of the AppRole auth method. Defaults to "approle".
     */
    public static final StringGuacamoleProperty VAULT_APPROLE_MOUNT =
            new StringGuacamoleProperty() {
                @Override
                public String getName() { return "vault-approle-mount"; }
            };

    /**
     * The AppRole role ID. Setting this (or {@link #VAULT_APPROLE_ROLE_ID_FILE})
     * makes the extension log in with AppRole and use short-lived tokens instead
     * of a static token.
     */
    public static final StringGuacamoleProperty VAULT_APPROLE_ROLE_ID =
            new StringGuacamoleProperty() {
                @Override
                public String getName() { return "vault-approle-role-id"; }
            };

    /**
     * Path to a file whose contents are the AppRole role ID. Takes effect only
     * when {@link #VAULT_APPROLE_ROLE_ID} is not set.
     */
    public static final StringGuacamoleProperty VAULT_APPROLE_ROLE_ID_FILE =
            new StringGuacamoleProperty() {
                @Override
                public String getName() { return "vault-approle-role-id-file"; }
            };

    /**
     * The AppRole secret ID. Optional only for roles with bind_secret_id=false.
     */
    public static final StringGuacamoleProperty VAULT_APPROLE_SECRET_ID =
            new StringGuacamoleProperty() {
                @Override
                public String getName() { return "vault-approle-secret-id"; }
            };

    /**
     * Path to a file whose contents are the AppRole secret ID. Read on every
     * login, so a rotated secret ID is picked up without restarting Guacamole.
     * Takes effect only when {@link #VAULT_APPROLE_SECRET_ID} is not set.
     */
    public static final StringGuacamoleProperty VAULT_APPROLE_SECRET_ID_FILE =
            new StringGuacamoleProperty() {
                @Override
                public String getName() { return "vault-approle-secret-id-file"; }
            };

    /**
     * The mount point of the SSH secrets engine within Vault. Defaults to "ssh".
     */
    public static final StringGuacamoleProperty VAULT_SSH_MOUNT =
            new StringGuacamoleProperty() {
                @Override
                public String getName() { return "vault-ssh-mount"; }
            };

    /**
     * The name of the OTP role configured on the SSH secrets engine. Required.
     */
    public static final StringGuacamoleProperty VAULT_SSH_ROLE =
            new StringGuacamoleProperty() {
                @Override
                public String getName() { return "vault-ssh-role"; }
            };

    /**
     * The name of the connection parameter token that will hold the generated
     * OTP. Defaults to "VAULT_SECRET". Reference it from a connection's
     * "password" parameter as ${VAULT_SECRET}.
     */
    public static final StringGuacamoleProperty VAULT_SECRET_TOKEN_NAME =
            new StringGuacamoleProperty() {
                @Override
                public String getName() { return "vault-secret-token-name"; }
            };

    /**
     * The mount point of the KV secrets engine used for RDP (and other static)
     * passwords. Defaults to "secret".
     */
    public static final StringGuacamoleProperty VAULT_KV_MOUNT =
            new StringGuacamoleProperty() {
                @Override
                public String getName() { return "vault-kv-mount"; }
            };

    /**
     * The KV secrets engine version, 1 or 2. Defaults to 2.
     */
    public static final IntegerGuacamoleProperty VAULT_KV_VERSION =
            new IntegerGuacamoleProperty() {
                @Override
                public String getName() { return "vault-kv-version"; }
            };

    /**
     * The path prefix under the KV mount where connection secrets live. The full
     * path is "<prefix>/<protocol>/<connection-name>". Defaults to "guacamole".
     */
    public static final StringGuacamoleProperty VAULT_KV_PREFIX =
            new StringGuacamoleProperty() {
                @Override
                public String getName() { return "vault-kv-prefix"; }
            };

    /**
     * The field within a KV secret that holds the password. Defaults to
     * "password".
     */
    public static final StringGuacamoleProperty VAULT_KV_PASSWORD_FIELD =
            new StringGuacamoleProperty() {
                @Override
                public String getName() { return "vault-kv-password-field"; }
            };

}
