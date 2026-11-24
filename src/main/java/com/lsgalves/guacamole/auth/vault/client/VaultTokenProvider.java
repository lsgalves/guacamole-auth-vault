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
 * has elapsed, revoking the token it replaces. If Vault denies a call, the
 * provider asks Vault whether the token itself is still valid
 * (auth/token/lookup-self): only if it is not (e.g. it was revoked) is the call
 * retried once after a fresh login. A denial for a valid token comes from the
 * policy and is returned as is. Logins happen on demand, so no background thread
 * is needed, and a Guacamole that was down for longer than the token TTL simply
 * logs in again.
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
     * Runs a Vault call with a valid token. If Vault denies the call because it
     * no longer accepts the token and the token can be replaced (AppRole), logs
     * in again and retries once.
     */
    public <T> T execute(VaultOperation<T> operation) throws GuacamoleException {

        String vaultAddr = confService.getVaultAddr();
        String token = getToken();

        try {
            return operation.execute(new VaultClient(vaultAddr, token));
        }
        catch (VaultPermissionDeniedException e) {

            // Only an AppRole token can be replaced, and replacing it only helps
            // if Vault stopped accepting it. A denial for a valid token comes
            // from the policy: logging in again would just mint another token.
            if (!confService.isAppRoleConfigured()
                    || !isRejected(vaultAddr, token, e))
                throw e;

            invalidate(token);
            logger.debug("Vault no longer accepts the cached token; logging in "
                    + "again with AppRole and retrying once.", e);
            return operation.execute(new VaultClient(vaultAddr, getToken()));
        }
    }

    /**
     * @return The token to use: the cached AppRole token (logging in first if
     *         there is none or it is due for refresh), or the static token.
     */
    private String getToken() throws GuacamoleException {

        if (!confService.isAppRoleConfigured())
            return confService.getVaultToken();

        String newToken;
        String replacedToken;
        synchronized (this) {
            if (cachedToken != null && System.currentTimeMillis() < refreshAtMillis)
                return cachedToken;

            // Null if there was no token yet or it was invalidated (already
            // rejected by Vault, so there is nothing to revoke).
            replacedToken = cachedToken;
            newToken = login();
        }

        // Outside the lock: revocation is a network call nobody has to wait for.
        if (replacedToken != null)
            revoke(replacedToken);

        return newToken;
    }

    /**
     * Logs in with AppRole and caches the token obtained. Must be called while
     * holding the lock on {@code this}.
     *
     * @return The new token.
     */
    private String login() throws GuacamoleException {

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
     * Revokes a token that a newer login has replaced, so it does not linger in
     * Vault until its TTL runs out. A call still in flight with it is denied,
     * finds the token rejected and is retried with the new one. Failures are
     * only logged: the token expires on its own anyway.
     */
    private void revoke(String token) {
        try {
            new VaultClient(confService.getVaultAddr(), token).revokeSelf();
            logger.debug("Revoked the replaced Vault AppRole token.");
        }
        catch (GuacamoleException e) {
            logger.warn("Unable to revoke the replaced Vault token; it will "
                    + "expire on its own: {}", e.getMessage());
            logger.debug("Vault token revocation failure.", e);
        }
    }

    /**
     * Tells whether a denial means Vault no longer accepts the token (expired,
     * revoked) rather than a policy that does not grant the path, by asking
     * Vault about the token itself.
     *
     * @param denial The original denial; a failed lookup is attached to it as a
     *               suppressed exception.
     * @return true only if Vault confirms it rejects the token.
     */
    private static boolean isRejected(String vaultAddr, String token,
            VaultPermissionDeniedException denial) {
        try {
            return !new VaultClient(vaultAddr, token).isTokenValid();
        }
        catch (GuacamoleException e) {
            // Unable to tell (e.g. Vault unreachable); a new login would not
            // help either.
            denial.addSuppressed(e);
            return false;
        }
    }

    /**
     * Drops the given token from the cache so the next call logs in again.
     */
    private synchronized void invalidate(String token) {
        // Another thread may already have replaced it; keep the newer token.
        if (token.equals(cachedToken))
            cachedToken = null;
    }

}
