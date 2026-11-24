package com.lsgalves.guacamole.auth.vault.client;

/**
 * A Vault token obtained through an auth method login, with its TTL.
 */
public final class VaultToken {

    private final String token;
    private final long leaseDurationSeconds;

    /**
     * @param token                The token value (auth.client_token).
     * @param leaseDurationSeconds The token TTL in seconds (auth.lease_duration);
     *                             0 means the token does not expire.
     */
    public VaultToken(String token, long leaseDurationSeconds) {
        this.token = token;
        this.leaseDurationSeconds = leaseDurationSeconds;
    }

    public String getToken() {
        return token;
    }

    public long getLeaseDurationSeconds() {
        return leaseDurationSeconds;
    }

}
