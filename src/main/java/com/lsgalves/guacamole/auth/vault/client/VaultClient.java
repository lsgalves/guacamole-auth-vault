package com.lsgalves.guacamole.auth.vault.client;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleServerException;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * Minimal client for HashiCorp Vault's SSH secrets engine, OTP mode.
 *
 * <p>Implemented with {@link HttpURLConnection} so it runs on the Java 8 runtime
 * shipped by the official Guacamole image.
 *
 * @see <a href="https://developer.hashicorp.com/vault/api-docs/secret/ssh">
 *      Vault SSH secrets engine API</a>
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
     * @param token     Vault token authorising OTP credential creation.
     */
    public VaultClient(String vaultAddr, String token) {
        this.vaultAddr = vaultAddr;
        this.token = token;
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
     * @throws GuacamoleException If the request fails or the response is invalid.
     */
    public String generateSshOtp(String mount, String role, String username,
            String ip) throws GuacamoleException {

        String url = vaultAddr + "/v1/" + mount + "/creds/" + role;

        ObjectNode body = MAPPER.createObjectNode();
        body.put("ip", ip);
        if (username != null && !username.isEmpty())
            body.put("username", username);
        byte[] payload = body.toString().getBytes(StandardCharsets.UTF_8);

        HttpURLConnection connection = null;
        try {
            connection = (HttpURLConnection) new URL(url).openConnection();
            connection.setConnectTimeout(CONNECT_TIMEOUT_MS);
            connection.setReadTimeout(READ_TIMEOUT_MS);
            connection.setRequestMethod("POST");
            connection.setRequestProperty("X-Vault-Token", token);
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setDoOutput(true);

            try (OutputStream out = connection.getOutputStream()) {
                out.write(payload);
            }

            int status = connection.getResponseCode();
            String responseBody = readBody(status / 100 == 2
                    ? connection.getInputStream()
                    : connection.getErrorStream());

            if (status / 100 != 2)
                throw new GuacamoleServerException(
                        "Vault returned HTTP " + status
                      + " when generating an SSH OTP (role=" + role
                      + ", ip=" + ip + "): " + responseBody);

            String otp = parseOtp(responseBody);
            if (otp == null || otp.isEmpty())
                throw new GuacamoleServerException(
                        "Vault response did not contain a 'data.key' OTP value.");

            return otp;
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

}
