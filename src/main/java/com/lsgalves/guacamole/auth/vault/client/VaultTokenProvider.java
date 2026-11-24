package com.lsgalves.guacamole.auth.vault.client;

import org.apache.guacamole.GuacamoleException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.lsgalves.guacamole.auth.vault.conf.VaultConfigurationService;

/**
 * Supplies the Vault token used by the extension and runs Vault calls with it.
 *
 * <p>With AppRole configured, the provider logs in on first use, caches the
 * short-lived token it gets back, and logs in again once most of the token's TTL
 * has elapsed. If Vault still rejects a token (e.g. it was revoked), the call is
 * retried once after a fresh login. Logins happen on demand, so no background
 * thread is needed, and a Guacamole that was down for longer than the token TTL
 * simply logs in again.
 *
 * <p>Without AppRole, the static token ("vault-token" / "vault-token-file") is
 * used as-is, re-read on every call.
 *
 * <p>One instance is shared by all users of the extension; it is thread-safe.
 */
public class VaultTokenProvider {

    private static final Logger logger =
            LoggerFactory.getLogger(VaultTokenProvider.class);

    /**
     * Fraction of an AppRole token's TTL after which a new login is performed,
     * leaving headroom so a token is never used right at its expiry.
     */
    private static final double REFRESH_AFTER_TTL_FRACTION = 0.8;

    private final VaultConfigurationService confService;

    /**
     * The cached AppRole token, or null if no login has happened yet or the
     * token was invalidated. Guarded by {@code this}.
     */
    private String cachedToken;

    /**
     * When (epoch millis) the cached token should be replaced by a new login.
     * Guarded by {@code this}.
     */
    private long refreshAtMillis;

    public VaultTokenProvider(VaultConfigurationService confService) {
        this.confService = confService;
    }

    /**
     * A Vault call to run with a client authenticated by this provider.
     */
    @FunctionalInterface
    public interface VaultOperation<T> {
        T execute(VaultClient client) throws GuacamoleException;
    }

    /**
     * Runs a Vault call with a valid token. If Vault denies the call and the
     * token can be replaced (AppRole), logs in again and retries once.
     */
    public <T> T execute(VaultOperation<T> operation) throws GuacamoleException {

        String vaultAddr = confService.getVaultAddr();
        String token = getToken();

        try {
            return operation.execute(new VaultClient(vaultAddr, token));
        }
        catch (VaultPermissionDeniedException e) {
            if (!invalidate(token))
                throw e;

            logger.debug("Vault denied the request; logging in again with "
                    + "AppRole and retrying once.", e);
            return operation.execute(new VaultClient(vaultAddr, getToken()));
        }
    }

    /**
     * @return The token to use: the cached AppRole token (logging in first if
     *         there is none or it is due for refresh), or the static token.
     */
    private synchronized String getToken() throws GuacamoleException {

        if (!confService.isAppRoleConfigured())
            return confService.getVaultToken();

        if (cachedToken != null && System.currentTimeMillis() < refreshAtMillis)
            return cachedToken;

        String mount = confService.getAppRoleMount();
        VaultToken login = new VaultClient(confService.getVaultAddr(), null)
                .loginWithAppRole(mount, confService.getAppRoleRoleId(),
                        confService.getAppRoleSecretId());

        long ttlSeconds = login.getLeaseDurationSeconds();
        cachedToken = login.getToken();
        refreshAtMillis = (ttlSeconds > 0)
                ? System.currentTimeMillis()
                        + (long) (ttlSeconds * 1000 * REFRESH_AFTER_TTL_FRACTION)
                : Long.MAX_VALUE;

        logger.info("Logged in to Vault with AppRole (mount={}); token TTL {}s.",
                mount, ttlSeconds > 0 ? ttlSeconds : "unlimited");

        return cachedToken;
    }

    /**
     * Drops the given token from the cache so the next call logs in again.
     *
     * @return Whether a new token can be obtained (true only with AppRole).
     */
    private synchronized boolean invalidate(String token)
            throws GuacamoleException {

        if (!confService.isAppRoleConfigured())
            return false;

        // Another thread may already have replaced it; keep the newer token.
        if (token.equals(cachedToken))
            cachedToken = null;

        return true;
    }

}
