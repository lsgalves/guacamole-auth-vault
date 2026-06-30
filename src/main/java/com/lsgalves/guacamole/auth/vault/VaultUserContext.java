package com.lsgalves.guacamole.auth.vault;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.net.auth.Connection;
import org.apache.guacamole.net.auth.TokenInjectingUserContext;
import org.apache.guacamole.net.auth.UserContext;
import org.apache.guacamole.protocol.GuacamoleConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.lsgalves.guacamole.auth.vault.client.VaultClient;
import com.lsgalves.guacamole.auth.vault.conf.VaultConfigurationService;

/**
 * Decorates an existing {@link UserContext} so that, whenever an SSH connection
 * is established, a one-time password is fetched from HashiCorp Vault and made
 * available as a connection parameter token (default {@code ${VAULT_SSH_OTP}}).
 *
 * <p>Tokens are computed lazily, only at connect time, so each connection
 * attempt consumes exactly one freshly generated OTP.
 */
public class VaultUserContext extends TokenInjectingUserContext {

    private static final Logger logger =
            LoggerFactory.getLogger(VaultUserContext.class);

    /**
     * The protocol this extension acts upon.
     */
    private static final String SSH_PROTOCOL = "ssh";

    private final VaultConfigurationService confService;

    public VaultUserContext(UserContext userContext,
            VaultConfigurationService confService) {
        super(userContext);
        this.confService = confService;
    }

    @Override
    protected Map<String, String> getTokens(Connection connection)
            throws GuacamoleException {

        GuacamoleConfiguration config = getConnectionConfiguration(connection);

        // Only act on SSH connections; leave everything else untouched.
        String protocol = config.getProtocol();
        if (protocol == null || !SSH_PROTOCOL.equalsIgnoreCase(protocol))
            return Collections.emptyMap();

        // Read via getParameters() (not getParameter()): JDBC's lazy
        // configuration only populates values when getParameters() is invoked.
        Map<String, String> parameters = config.getParameters();

        // Opt-in: only act when the password parameter actually references our
        // token (e.g. password = ${VAULT_SSH_OTP}). SSH connections using a
        // static password, a key, or any other credential are left untouched —
        // and, crucially, no Vault call is made for them.
        String tokenName = confService.getOtpTokenName();
        String tokenReference = "${" + tokenName + "}";
        String password = parameters.get("password");
        if (password == null || !password.contains(tokenReference))
            return Collections.emptyMap();

        String hostname = parameters.get("hostname");
        String username = parameters.get("username");

        if (hostname == null || hostname.trim().isEmpty())
            throw new GuacamoleException(
                    "SSH connection \"" + connection.getName()
                  + "\" has no hostname; cannot request a Vault SSH OTP.");

        // Vault's SSH OTP is bound to a target IP address.
        String ip = resolveToIp(hostname.trim());

        VaultClient client = new VaultClient(
                confService.getVaultAddr(), confService.getVaultToken());

        String otp = client.generateSshOtp(
                confService.getSshMount(), confService.getSshRole(),
                username, ip);

        logger.info("Injected Vault SSH OTP into token ${{}} for connection "
                + "\"{}\" (user={}, host={}, ip={}).",
                tokenName, connection.getName(), username, hostname, ip);

        Map<String, String> tokens = new HashMap<>();
        tokens.put(tokenName, otp);
        return tokens;
    }

    /**
     * Returns the full configuration (including parameter values) for the given
     * connection.
     *
     * <p>Database-backed connections (e.g. guacamole-auth-jdbc-mysql) mask their
     * parameters in the normal, permission-checked view, so {@code hostname} and
     * {@code username} come back empty. Retrieving the connection through the
     * <em>privileged</em> directory yields a configuration with the real values.
     * Falls back to the connection's own configuration (e.g. file-based auth,
     * which already exposes parameters).
     */
    private GuacamoleConfiguration getConnectionConfiguration(Connection connection)
            throws GuacamoleException {

        Connection privileged = getPrivileged()
                .getConnectionDirectory().get(connection.getIdentifier());

        if (privileged != null)
            return privileged.getConfiguration();

        return connection.getConfiguration();
    }

    /**
     * Resolves a hostname to an IPv4/IPv6 literal. If the value is already an IP
     * address, it is returned unchanged.
     */
    private static String resolveToIp(String hostname) throws GuacamoleException {
        try {
            return InetAddress.getByName(hostname).getHostAddress();
        }
        catch (UnknownHostException e) {
            throw new GuacamoleException(
                    "Unable to resolve SSH host \"" + hostname
                  + "\" to an IP address for Vault OTP generation.", e);
        }
    }

}
