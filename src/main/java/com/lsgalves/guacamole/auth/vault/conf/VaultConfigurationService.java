package com.lsgalves.guacamole.auth.vault.conf;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleServerException;
import org.apache.guacamole.environment.Environment;
import org.apache.guacamole.environment.LocalEnvironment;
import org.apache.guacamole.properties.StringGuacamoleProperty;

/**
 * Reads and exposes the extension's configuration from guacamole.properties.
 */
public class VaultConfigurationService {

    /**
     * The Guacamole server environment, used to read guacamole.properties.
     */
    private final Environment environment = LocalEnvironment.getInstance();

    /**
     * @return The base URL of the Vault server (vault-addr).
     */
    public String getVaultAddr() throws GuacamoleException {
        return stripTrailingSlash(
                environment.getRequiredProperty(VaultProperties.VAULT_ADDR));
    }

    /**
     * @return The SSH secrets engine mount point (vault-ssh-mount), default "ssh".
     */
    public String getSshMount() throws GuacamoleException {
        return environment.getProperty(VaultProperties.VAULT_SSH_MOUNT, "ssh");
    }

    /**
     * @return The OTP role name (vault-ssh-role).
     */
    public String getSshRole() throws GuacamoleException {
        return environment.getRequiredProperty(VaultProperties.VAULT_SSH_ROLE);
    }

    /**
     * @return The connection parameter token name to populate with the secret,
     *         default "VAULT_SECRET".
     */
    public String getSecretTokenName() throws GuacamoleException {
        return environment.getProperty(VaultProperties.VAULT_SECRET_TOKEN_NAME,
                "VAULT_SECRET");
    }

    /**
     * @return The KV secrets engine mount point (vault-kv-mount), default "secret".
     */
    public String getKvMount() throws GuacamoleException {
        return environment.getProperty(VaultProperties.VAULT_KV_MOUNT, "secret");
    }

    /**
     * @return The KV secrets engine version (vault-kv-version), default 2.
     */
    public int getKvVersion() throws GuacamoleException {
        return environment.getProperty(VaultProperties.VAULT_KV_VERSION, 2);
    }

    /**
     * @return The path prefix under the KV mount (vault-kv-prefix), default
     *         "guacamole".
     */
    public String getKvPrefix() throws GuacamoleException {
        return environment.getProperty(VaultProperties.VAULT_KV_PREFIX, "guacamole");
    }

    /**
     * @return The KV secret field holding the password (vault-kv-password-field),
     *         default "password".
     */
    public String getKvPasswordField() throws GuacamoleException {
        return environment.getProperty(VaultProperties.VAULT_KV_PASSWORD_FIELD,
                "password");
    }

    /**
     * @return Whether AppRole login is configured (a role ID is set), in which
     *         case it takes precedence over a static token.
     */
    public boolean isAppRoleConfigured() throws GuacamoleException {
        return getAppRoleRoleId() != null;
    }

    /**
     * @return The AppRole auth method mount point (vault-approle-mount), default
     *         "approle".
     */
    public String getAppRoleMount() throws GuacamoleException {
        return environment.getProperty(VaultProperties.VAULT_APPROLE_MOUNT,
                "approle");
    }

    /**
     * @return The AppRole role ID, from "vault-approle-role-id" or the file named
     *         by "vault-approle-role-id-file", or null if neither is set.
     */
    public String getAppRoleRoleId() throws GuacamoleException {
        return readInlineOrFile(VaultProperties.VAULT_APPROLE_ROLE_ID,
                VaultProperties.VAULT_APPROLE_ROLE_ID_FILE, "AppRole role ID");
    }

    /**
     * @return The AppRole secret ID, from "vault-approle-secret-id" or the file
     *         named by "vault-approle-secret-id-file", or null if neither is set
     *         (valid only for roles with bind_secret_id=false).
     */
    public String getAppRoleSecretId() throws GuacamoleException {
        return readInlineOrFile(VaultProperties.VAULT_APPROLE_SECRET_ID,
                VaultProperties.VAULT_APPROLE_SECRET_ID_FILE, "AppRole secret ID");
    }

    /**
     * Resolves the static Vault token, preferring the inline "vault-token"
     * property and falling back to the contents of the file named by
     * "vault-token-file". The token file is read fresh on each call so
     * externally-rotated tokens are picked up without restarting Guacamole.
     *
     * @return The Vault token to authenticate requests.
     * @throws GuacamoleException If neither property is configured or the token
     *         file cannot be read.
     */
    public String getVaultToken() throws GuacamoleException {

        String token = readInlineOrFile(VaultProperties.VAULT_TOKEN,
                VaultProperties.VAULT_TOKEN_FILE, "Vault token");
        if (token != null)
            return token;

        throw new GuacamoleServerException(
                "No Vault credentials configured. Set \"vault-approle-role-id\" "
              + "(or \"vault-approle-role-id-file\") for AppRole, or "
              + "\"vault-token\" (or \"vault-token-file\") in guacamole.properties.");
    }

    /**
     * Returns the trimmed value of the inline property if set, otherwise the
     * trimmed contents of the file named by the file property (read fresh on
     * each call), otherwise null.
     */
    private String readInlineOrFile(StringGuacamoleProperty inlineProperty,
            StringGuacamoleProperty fileProperty, String description)
            throws GuacamoleException {

        String value = environment.getProperty(inlineProperty);
        if (value != null && !value.trim().isEmpty())
            return value.trim();

        String file = environment.getProperty(fileProperty);
        if (file != null && !file.trim().isEmpty()) {
            try {
                return new String(Files.readAllBytes(Paths.get(file.trim())),
                        StandardCharsets.UTF_8).trim();
            }
            catch (IOException e) {
                throw new GuacamoleServerException(
                        "Unable to read " + description + " from file: " + file, e);
            }
        }

        return null;
    }

    private static String stripTrailingSlash(String url) {
        if (url != null && url.endsWith("/"))
            return url.substring(0, url.length() - 1);
        return url;
    }

}
