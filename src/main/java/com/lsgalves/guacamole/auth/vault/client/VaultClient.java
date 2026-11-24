package com.lsgalves.guacamole.auth.vault.client;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleServerException;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * Minimal client for HashiCorp Vault, covering AppRole login, the SSH secrets
 * engine (OTP mode) and the KV secrets engine (v1 and v2).
 *
 * <p>Implemented with {@link HttpURLConnection} so it runs on the Java 8 runtime
 * shipped by the official Guacamole image.
 *
 * @see <a href="https://developer.hashicorp.com/vault/api-docs/auth/approle">
 *      Vault AppRole auth method API</a>
 * @see <a href="https://developer.hashicorp.com/vault/api-docs/secret/ssh">
 *      Vault SSH secrets engine API</a>
 * @see <a href="https://developer.hashicorp.com/vault/api-docs/secret/kv">
 *      Vault KV secrets engine API</a>
 */
public class VaultClient {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final int CONNECT_TIMEOUT_MS = 10_000;
    private static final int READ_TIMEOUT_MS = 15_000;

    private final String vaultAddr;
    private final String token;

    /**
     * Creates a Vault client.
     *
     * @param vaultAddr Base Vault URL (no trailing slash), e.g. "http://vault:8200".
     * @param token     Vault token sent with each request, or null for
     *                  unauthenticated calls such as {@link #loginWithAppRole}.
     */
    public VaultClient(String vaultAddr, String token) {
        this.vaultAddr = vaultAddr;
        this.token = token;
    }

    /**
     * Logs in with the AppRole auth method.
     *
     * <p>Calls {@code POST /v1/auth/<mount>/login} with the role ID and (when the
     * role requires it) the secret ID, and returns the issued token together with
     * its TTL ({@code auth.client_token} / {@code auth.lease_duration}).
     *
     * @param mount    The AppRole auth method mount point (e.g. "approle").
     * @param roleId   The role ID.
     * @param secretId The secret ID, or null if the role has bind_secret_id=false.
     * @return The issued token.
     * @throws GuacamoleException If the login fails or the response is invalid.
     */
    public VaultToken loginWithAppRole(String mount, String roleId,
            String secretId) throws GuacamoleException {

        String url = vaultAddr + "/v1/auth/" + mount + "/login";

        ObjectNode body = MAPPER.createObjectNode();
        body.put("role_id", roleId);
        if (secretId != null && !secretId.isEmpty())
            body.put("secret_id", secretId);

        Response response = send("POST", url, body);
        if (!response.isSuccess())
            throw new GuacamoleServerException(
                    "Vault returned HTTP " + response.status
                  + " on AppRole login (mount=" + mount + "): " + response.body);

        try {
            JsonNode auth = MAPPER.readTree(response.body).path("auth");
            String clientToken = auth.path("client_token").asText(null);
            if (clientToken == null || clientToken.isEmpty())
                throw new GuacamoleServerException(
                        "Vault AppRole login response did not contain "
                      + "an 'auth.client_token' value.");
            return new VaultToken(clientToken,
                    auth.path("lease_duration").asLong(0));
        }
        catch (IOException e) {
            throw new GuacamoleServerException(
                    "Unable to parse Vault AppRole login response.", e);
        }
    }

    /**
     * Requests a one-time SSH password from Vault for the given user and host.
     *
     * <p>Calls {@code POST /v1/<mount>/creds/<role>} with the target username and
     * IP, and returns the {@code data.key} field of the response (the OTP).
     *
     * @param mount    The SSH secrets engine mount point (e.g. "ssh").
     * @param role     The OTP role name.
     * @param username The remote SSH username the OTP is generated for.
     * @param ip       The IP address of the target host.
     * @return The generated one-time password.
     * @throws VaultPermissionDeniedException If Vault rejects the token.
     * @throws GuacamoleException If the request fails or the response is invalid.
     */
    public String generateSshOtp(String mount, String role, String username,
            String ip) throws GuacamoleException {

        String url = vaultAddr + "/v1/" + mount + "/creds/" + role;

        ObjectNode body = MAPPER.createObjectNode();
        body.put("ip", ip);
        if (username != null && !username.isEmpty())
            body.put("username", username);

        Response response = send("POST", url, body);

        if (response.status == HttpURLConnection.HTTP_FORBIDDEN)
            throw new VaultPermissionDeniedException(
                    "Vault denied SSH OTP generation (role=" + role
                  + ", ip=" + ip + "): " + response.body);

        if (!response.isSuccess())
            throw new GuacamoleServerException(
                    "Vault returned HTTP " + response.status
                  + " when generating an SSH OTP (role=" + role
                  + ", ip=" + ip + "): " + response.body);

        String otp = parseOtp(response.body);
        if (otp == null || otp.isEmpty())
            throw new GuacamoleServerException(
                    "Vault response did not contain a 'data.key' OTP value.");

        return otp;
    }

    /**
     * Reads a single field from a secret stored in Vault's KV secrets engine.
     *
     * <p>For KV v2 the request path is {@code <mount>/data/<path>} and the value
     * lives under {@code data.data.<field>}; for KV v1 it is {@code <mount>/<path>}
     * with the value under {@code data.<field>}. Each path segment is URL-encoded,
     * so connection names containing spaces or punctuation are handled.
     *
     * @param mount    The KV mount point (e.g. "secret").
     * @param kvVersion The KV engine version, 1 or 2.
     * @param path     The secret path under the mount (e.g. "guacamole/rdp/My Server").
     * @param field    The field within the secret to return (e.g. "password").
     * @return The field's value.
     * @throws VaultPermissionDeniedException If Vault rejects the token.
     * @throws GuacamoleException If the secret or field is missing, or the request fails.
     */
    public String readKvSecret(String mount, int kvVersion, String path,
            String field) throws GuacamoleException {

        String apiPath = (kvVersion == 2)
                ? mount + "/data/" + encodePath(path)
                : mount + "/" + encodePath(path);
        String url = vaultAddr + "/v1/" + apiPath;

        Response response = send("GET", url, null);

        if (response.status == HttpURLConnection.HTTP_NOT_FOUND)
            throw new GuacamoleServerException(
                    "No Vault KV secret found at \"" + mount + "/" + path
                  + "\" (KV v" + kvVersion + ").");

        if (response.status == HttpURLConnection.HTTP_FORBIDDEN)
            throw new VaultPermissionDeniedException(
                    "Vault denied reading KV secret \"" + mount + "/" + path
                  + "\": " + response.body);

        if (!response.isSuccess())
            throw new GuacamoleServerException(
                    "Vault returned HTTP " + response.status + " when reading KV secret \""
                  + mount + "/" + path + "\": " + response.body);

        String value = parseKvField(response.body, kvVersion, field);
        if (value == null || value.isEmpty())
            throw new GuacamoleServerException(
                    "Vault KV secret \"" + mount + "/" + path
                  + "\" has no \"" + field + "\" field.");

        return value;
    }

    /**
     * Sends a request to Vault and returns its status and body. The token, if
     * any, is sent as {@code X-Vault-Token}; a non-null body is sent as JSON.
     */
    private Response send(String method, String url, JsonNode body)
            throws GuacamoleException {

        HttpURLConnection connection = null;
        try {
            connection = (HttpURLConnection) new URL(url).openConnection();
            connection.setConnectTimeout(CONNECT_TIMEOUT_MS);
            connection.setReadTimeout(READ_TIMEOUT_MS);
            connection.setRequestMethod(method);
            if (token != null)
                connection.setRequestProperty("X-Vault-Token", token);

            if (body != null) {
                connection.setRequestProperty("Content-Type", "application/json");
                connection.setDoOutput(true);
                try (OutputStream out = connection.getOutputStream()) {
                    out.write(body.toString().getBytes(StandardCharsets.UTF_8));
                }
            }

            int status = connection.getResponseCode();
            String responseBody = readBody(status / 100 == 2
                    ? connection.getInputStream()
                    : connection.getErrorStream());
            return new Response(status, responseBody);
        }
        catch (IOException e) {
            throw new GuacamoleServerException(
                    "Failed to contact Vault at " + url, e);
        }
        finally {
            if (connection != null)
                connection.disconnect();
        }
    }

    private static String parseKvField(String responseBody, int kvVersion,
            String field) throws GuacamoleException {
        try {
            JsonNode data = MAPPER.readTree(responseBody).path("data");
            // KV v2 nests the secret payload under data.data; v1 puts it in data.
            JsonNode payload = (kvVersion == 2) ? data.path("data") : data;
            return payload.path(field).asText(null);
        }
        catch (IOException e) {
            throw new GuacamoleServerException(
                    "Unable to parse Vault KV response.", e);
        }
    }

    /**
     * URL-encodes each segment of a Vault path while preserving the "/"
     * separators, so values like "My RDP Server" become "My%20RDP%20Server".
     */
    private static String encodePath(String path) {
        String[] segments = path.split("/");
        StringBuilder encoded = new StringBuilder();
        for (int i = 0; i < segments.length; i++) {
            if (i > 0)
                encoded.append('/');
            encoded.append(encodeSegment(segments[i]));
        }
        return encoded.toString();
    }

    private static String encodeSegment(String segment) {
        try {
            // URLEncoder is form-encoding; turn "+" back into a path-safe "%20".
            return URLEncoder.encode(segment, "UTF-8").replace("+", "%20");
        }
        catch (UnsupportedEncodingException e) {
            // UTF-8 is always available.
            throw new IllegalStateException(e);
        }
    }

    private static String readBody(InputStream stream) throws IOException {
        if (stream == null)
            return "";
        try (InputStream in = stream) {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            byte[] chunk = new byte[4096];
            int read;
            while ((read = in.read(chunk)) != -1)
                buffer.write(chunk, 0, read);
            return new String(buffer.toByteArray(), StandardCharsets.UTF_8);
        }
    }

    private static String parseOtp(String responseBody)
            throws GuacamoleException {
        try {
            JsonNode root = MAPPER.readTree(responseBody);
            return root.path("data").path("key").asText(null);
        }
        catch (IOException e) {
            throw new GuacamoleServerException(
                    "Unable to parse Vault OTP response.", e);
        }
    }

    /**
     * The status code and body of a Vault HTTP response.
     */
    private static final class Response {

        final int status;
        final String body;

        Response(int status, String body) {
            this.status = status;
            this.body = body;
        }

        boolean isSuccess() {
            return status / 100 == 2;
        }

    }

}
