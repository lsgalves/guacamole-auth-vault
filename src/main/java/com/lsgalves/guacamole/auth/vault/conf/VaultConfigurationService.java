package com.lsgalves.guacamole.auth.vault.conf;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleServerException;
import org.apache.guacamole.environment.Environment;
import org.apache.guacamole.environment.LocalEnvironment;

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
     * @return The connection parameter token name to populate with the OTP,
     *         default "VAULT_SSH_OTP".
     */
    public String getOtpTokenName() throws GuacamoleException {
        return environment.getProperty(VaultProperties.VAULT_OTP_TOKEN_NAME,
                "VAULT_SSH_OTP");
    }

    /**
     * Resolves the Vault token, preferring the inline "vault-token" property and
     * falling back to the contents of the file named by "vault-token-file". The
     * token file is read fresh on each call so externally-rotated tokens are
     * picked up without restarting Guacamole.
     *
     * @return The Vault token to authenticate OTP requests.
     * @throws GuacamoleException If neither property is configured or the token
     *         file cannot be read.
     */
    public String getVaultToken() throws GuacamoleException {

        String token = environment.getProperty(VaultProperties.VAULT_TOKEN);
        if (token != null && !token.trim().isEmpty())
            return token.trim();

        String tokenFile = environment.getProperty(VaultProperties.VAULT_TOKEN_FILE);
        if (tokenFile != null && !tokenFile.trim().isEmpty()) {
            try {
                return new String(Files.readAllBytes(Paths.get(tokenFile.trim())),
                        StandardCharsets.UTF_8).trim();
            }
            catch (IOException e) {
                throw new GuacamoleServerException(
                        "Unable to read Vault token from file: " + tokenFile, e);
            }
        }

        throw new GuacamoleServerException(
                "No Vault token configured. Set either \"vault-token\" or "
              + "\"vault-token-file\" in guacamole.properties.");
    }

    private static String stripTrailingSlash(String url) {
        if (url != null && url.endsWith("/"))
            return url.substring(0, url.length() - 1);
        return url;
    }

}
