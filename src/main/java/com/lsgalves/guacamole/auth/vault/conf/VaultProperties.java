package com.lsgalves.guacamole.auth.vault.conf;

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
     * A Vault token used by this extension to request SSH OTP credentials.
     * Either this or {@link #VAULT_TOKEN_FILE} must be provided.
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
     * OTP. Defaults to "VAULT_SSH_OTP". Reference it from a connection's
     * "password" parameter as ${VAULT_SSH_OTP}.
     */
    public static final StringGuacamoleProperty VAULT_OTP_TOKEN_NAME =
            new StringGuacamoleProperty() {
                @Override
                public String getName() { return "vault-otp-token-name"; }
            };

}
