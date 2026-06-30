package com.lsgalves.guacamole.auth.vault;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.net.auth.AbstractAuthenticationProvider;
import org.apache.guacamole.net.auth.AuthenticatedUser;
import org.apache.guacamole.net.auth.Credentials;
import org.apache.guacamole.net.auth.UserContext;

import com.lsgalves.guacamole.auth.vault.conf.VaultConfigurationService;

/**
 * Authentication provider that does not authenticate users of its own, but
 * decorates the user context produced by other authentication providers so that
 * SSH connections receive a one-time password fetched from HashiCorp Vault.
 */
public class VaultAuthenticationProvider extends AbstractAuthenticationProvider {

    private final VaultConfigurationService confService =
            new VaultConfigurationService();

    @Override
    public String getIdentifier() {
        return "vault-ssh-otp";
    }

    @Override
    public UserContext decorate(UserContext context,
            AuthenticatedUser authenticatedUser, Credentials credentials)
            throws GuacamoleException {
        return new VaultUserContext(context, confService);
    }

    @Override
    public UserContext redecorate(UserContext decorated, UserContext context,
            AuthenticatedUser authenticatedUser, Credentials credentials)
            throws GuacamoleException {
        return new VaultUserContext(context, confService);
    }

}
