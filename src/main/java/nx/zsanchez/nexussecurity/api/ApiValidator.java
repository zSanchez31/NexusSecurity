package nx.zsanchez.nexussecurity.api;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import nx.zsanchez.nexussecurity.NexusSecurity;
import nx.zsanchez.nexussecurity.api.model.SubscriptionResponse;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.logging.Logger;

/**
 * Handles HTTP communication with the NexusSecurity subscription validation API.
 * All network calls are blocking and MUST be called from async threads only.
 *
 * <p>Retry logic: On failure, retries up to {@code maxRetries} times with exponential backoff.
 * Failed attempts are logged with their reason for audit purposes.</p>
 *
 * <p>Security: The API key is sent via Authorization header, never in the URL.</p>
 */
public class ApiValidator {

    private final NexusSecurity plugin;
    private final Logger logger;
    private final Gson gson;

    private final String validationEndpoint;
    private final int timeoutSeconds;
    private final int maxRetries;
    private final String userAgent;

    /**
     * Creates the API validator with config from plugin settings.
     *
     * @param plugin Main plugin instance
     */
    public ApiValidator(NexusSecurity plugin) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
        this.gson = new Gson();
        this.validationEndpoint = plugin.getConfig().getString(
                "api.validation-endpoint", "https://api.nexussecurity.io/v1/validate");
        this.timeoutSeconds = plugin.getConfig().getInt("api.timeout-seconds", 10);
        this.maxRetries = plugin.getConfig().getInt("api.max-retries", 3);
        this.userAgent = "NexusSecurity/" + plugin.getDescription().getVersion() +
                " (Minecraft " + plugin.getServer().getBukkitVersion() + ")";
    }

    /**
     * Validates the API key against the subscription server.
     * Retries up to {@code maxRetries} times with exponential backoff on network errors.
     *
     * @param apiKey The API key to validate
     * @return A {@link SubscriptionResponse} with validation results
     */
    public SubscriptionResponse validate(String apiKey) {
        if (apiKey == null || apiKey.isBlank() || apiKey.equals("TU_CLAVE_API_AQUI")) {
            logger.warning("[ApiValidator] No valid API key configured. Plugin will run in LIMITED mode.");
            return SubscriptionResponse.invalid("API key not configured");
        }

        // Support for local Development / Test API Keys without requiring a remote licensing server
        String upperKey = apiKey.toUpperCase().trim();
        boolean isDevMode = plugin.getConfig().getBoolean("api.dev-mode", false);
        if (isDevMode || upperKey.startsWith("DEV-") || upperKey.startsWith("TEST-") || upperKey.equals("DEV-NEXUS-KEY")) {
            logger.info("[ApiValidator] 🧪 Development / Test API Key detected ('" + apiKey + "'). Bypassing remote validation; FULL mode activated.");
            long oneYearFromNow = System.currentTimeMillis() + (365L * 24 * 60 * 60 * 1000);
            return SubscriptionResponse.valid("DEVELOPMENT", oneYearFromNow, "Dev/Test API Key active");
        }

        SubscriptionResponse lastError = null;
        for (int attempt = 1; attempt <= maxRetries; attempt++) {
            try {
                SubscriptionResponse response = performRequest(apiKey);
                if (attempt > 1) {
                    logger.info("[ApiValidator] Validation succeeded on attempt " + attempt);
                }
                return response;
            } catch (IOException e) {
                lastError = SubscriptionResponse.invalid("Network error: " + e.getMessage());
                logger.warning("[ApiValidator] Validation attempt " + attempt + "/" + maxRetries +
                        " failed: " + e.getMessage());

                if (attempt < maxRetries) {
                    // Exponential backoff: 1s, 2s, 4s...
                    long backoffMs = (long) Math.pow(2, attempt - 1) * 1000;
                    try {
                        Thread.sleep(backoffMs);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
            } catch (Exception e) {
                logger.severe("[ApiValidator] Unexpected error during validation: " + e.getMessage());
                lastError = SubscriptionResponse.invalid("Unexpected error: " + e.getMessage());
                break;
            }
        }

        logger.warning("[ApiValidator] All " + maxRetries + " validation attempts failed.");
        return lastError != null ? lastError : SubscriptionResponse.invalid("Unknown validation error");
    }

    /**
     * Performs a single HTTP request to the validation endpoint.
     *
     * @param apiKey The API key to send
     * @return Parsed SubscriptionResponse
     * @throws IOException if network or parsing fails
     */
    private SubscriptionResponse performRequest(String apiKey) throws IOException {
        HttpURLConnection connection = null;
        try {
            URL url = new URI(validationEndpoint).toURL();
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            connection.setConnectTimeout(timeoutSeconds * 1000);
            connection.setReadTimeout(timeoutSeconds * 1000);
            connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setRequestProperty("Accept", "application/json");
            connection.setRequestProperty("Authorization", "Bearer " + apiKey);
            connection.setRequestProperty("User-Agent", userAgent);
            connection.setRequestProperty("X-Server-Version", plugin.getServer().getVersion());

            // Build request body
            JsonObject body = new JsonObject();
            body.addProperty("serverId", plugin.getServerId());
            body.addProperty("serverVersion", plugin.getServer().getBukkitVersion());
            body.addProperty("pluginVersion", plugin.getDescription().getVersion());

            byte[] requestBody = body.toString().getBytes(StandardCharsets.UTF_8);
            connection.setRequestProperty("Content-Length", String.valueOf(requestBody.length));

            try (OutputStream os = connection.getOutputStream()) {
                os.write(requestBody);
            }

            int responseCode = connection.getResponseCode();

            // Read response body
            InputStream inputStream = responseCode >= 200 && responseCode < 300
                    ? connection.getInputStream()
                    : connection.getErrorStream();

            String responseBody = "";
            if (inputStream != null) {
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(inputStream, StandardCharsets.UTF_8))) {
                    StringBuilder sb = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        sb.append(line);
                    }
                    responseBody = sb.toString();
                }
            }

            if (responseCode == 200) {
                SubscriptionResponse response = gson.fromJson(responseBody, SubscriptionResponse.class);
                if (response == null) {
                    throw new IOException("Empty or unparseable API response");
                }
                logger.fine("[ApiValidator] Validation response: " + response);
                return response;
            } else if (responseCode == 401 || responseCode == 403) {
                logger.warning("[ApiValidator] API key rejected by server (HTTP " + responseCode + ")");
                return SubscriptionResponse.invalid("API key rejected (HTTP " + responseCode + ")");
            } else if (responseCode == 402) {
                logger.warning("[ApiValidator] Subscription expired (HTTP 402)");
                return SubscriptionResponse.invalid("Subscription expired");
            } else {
                throw new IOException("HTTP " + responseCode + ": " + responseBody.substring(0, Math.min(200, responseBody.length())));
            }

        } catch (URISyntaxException e) {
            throw new IOException("Invalid validation endpoint URL: " + e.getMessage());
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    /**
     * Performs a lightweight ping to check if the API server is reachable.
     * Used by SubscriptionManager to detect connectivity restoration.
     *
     * @return true if the API server responds
     */
    public boolean isApiReachable() {
        try {
            URL url = new URI(validationEndpoint).toURL();
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);
            conn.setRequestMethod("GET");
            int code = conn.getResponseCode();
            conn.disconnect();
            return code > 0;
        } catch (Exception e) {
            return false;
        }
    }
}
