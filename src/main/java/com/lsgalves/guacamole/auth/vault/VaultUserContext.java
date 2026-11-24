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

import com.lsgalves.guacamole.auth.vault.client.VaultTokenProvider;
import com.lsgalves.guacamole.auth.vault.conf.VaultConfigurationService;

/**
 * Decorates an existing {@link UserContext} so that, at connect time, the secret
 * for a connection is fetched from HashiCorp Vault and exposed as a connection
 * parameter token (default {@code ${VAULT_SECRET}}). Two protocols are handled:
 *
 * <ul>
 *   <li><b>SSH</b> — a one-time password is generated via Vault's SSH secrets
 *       engine (OTP mode).</li>
 *   <li><b>RDP</b> — a static password is read from a Vault KV secrets engine,
 *       at a path derived from the protocol and connection name
 *       ({@code <prefix>/<protocol>/<connection-name>}).</li>
 * </ul>
 *
 * <p>In both cases the extension only acts when the connection's {@code password}
 * parameter references the token (e.g. {@code password = ${VAULT_SECRET}}), and
 * tokens are computed lazily, only when the connection is actually opened.
 */
public class VaultUserContext extends TokenInjectingUserContext {

    private static final Logger logger =
            LoggerFactory.getLogger(VaultUserContext.class);

    private static final String SSH_PROTOCOL = "ssh";
    private static final String RDP_PROTOCOL = "rdp";

    private final VaultConfigurationService confService;

    private final VaultTokenProvider tokenProvider;

    public VaultUserContext(UserContext userContext,
            VaultConfigurationService confService,
            VaultTokenProvider tokenProvider) {
        super(userContext);
        this.confService = confService;
        this.tokenProvider = tokenProvider;
    }

    @Override
    protected Map<String, String> getTokens(Connection connection)
            throws GuacamoleException {

        GuacamoleConfiguration config = getConnectionConfiguration(connection);

        String protocol = config.getProtocol();
        if (protocol == null)
            return Collections.emptyMap();

        // Read via getParameters() (not getParameter()): JDBC's lazy
        // configuration only populates values when getParameters() is invoked.
        Map<String, String> parameters = config.getParameters();

        // Opt-in: only act when the password parameter actually references our
        // token (e.g. password = ${VAULT_SECRET}). Connections using a static
        // password, a key, or any other credential are left untouched — and,
        // crucially, no Vault call is made for them.
        String tokenName = confService.getSecretTokenName();
        String tokenReference = "${" + tokenName + "}";
        String password = parameters.get("password");
        if (password == null || !password.contains(tokenReference))
            return Collections.emptyMap();

        // Dispatch to the appropriate Vault backend by protocol.
        String secret;
        if (SSH_PROTOCOL.equalsIgnoreCase(protocol))
            secret = fetchSshOtp(connection, parameters);
        else if (RDP_PROTOCOL.equalsIgnoreCase(protocol))
            secret = fetchKvPassword(connection, RDP_PROTOCOL);
        else
            // Token present but on a protocol we don't handle; leave untouched.
            return Collections.emptyMap();

        Map<String, String> tokens = new HashMap<>();
        tokens.put(tokenName, secret);
        return tokens;
    }

    /**
     * Generates a one-time SSH password via Vault's SSH secrets engine, bound to
     * the connection's target host (resolved to an IP) and username.
     */
    private String fetchSshOtp(Connection connection,
            Map<String, String> parameters) throws GuacamoleException {

        String hostname = parameters.get("hostname");
        String username = parameters.get("username");

        if (hostname == null || hostname.trim().isEmpty())
            throw new GuacamoleException(
                    "SSH connection \"" + connection.getName()
                  + "\" has no hostname; cannot request a Vault SSH OTP.");

        // Vault's SSH OTP is bound to a target IP address.
        String ip = resolveToIp(hostname.trim());

        String otp = tokenProvider.execute(client -> client.generateSshOtp(
                confService.getSshMount(), confService.getSshRole(),
                username, ip));

        logger.info("Injected Vault SSH OTP into token ${{}} for connection "
                + "\"{}\" (user={}, host={}, ip={}).",
                confService.getSecretTokenName(), connection.getName(),
                username, hostname, ip);

        return otp;
    }

    /**
     * Reads a static password from Vault's KV secrets engine. The path follows
     * the convention {@code <prefix>/<protocol>/<connection-name>} under the
     * configured KV mount, and the password is taken from the configured field
     * (default {@code password}).
     */
    private String fetchKvPassword(Connection connection, String protocol)
            throws GuacamoleException {

        String name = connection.getName();
        if (name == null || name.trim().isEmpty())
            throw new GuacamoleException(
                    "Connection has no name; cannot build a Vault KV path "
                  + "for protocol \"" + protocol + "\".");

        // e.g. "guacamole/rdp/My RDP Server"
        String path = confService.getKvPrefix() + "/" + protocol + "/" + name.trim();

        String password = tokenProvider.execute(client -> client.readKvSecret(
                confService.getKvMount(), confService.getKvVersion(),
                path, confService.getKvPasswordField()));

        logger.info("Injected Vault KV secret into token ${{}} for {} connection "
                + "\"{}\" (kv path: {}/{}).",
                confService.getSecretTokenName(), protocol, name,
                confService.getKvMount(), path);

        return password;
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
