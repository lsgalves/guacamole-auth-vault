package com.lsgalves.guacamole.auth.vault.client;

import org.apache.guacamole.GuacamoleServerException;

/**
 * Thrown when Vault answers HTTP 403. Vault uses this status both for a policy
 * that doesn't grant the path and for an expired or revoked token, so callers
 * holding a renewable credential (AppRole) check the token first
 * ({@link VaultClient#isTokenValid()}) and log in again only if it was rejected.
 */
public class VaultPermissionDeniedException extends GuacamoleServerException {

    public VaultPermissionDeniedException(String message) {
        super(message);
    }

}
