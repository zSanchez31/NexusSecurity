package nx.zsanchez.nexussecurity.modules.shield;

import nx.zsanchez.nexussecurity.NexusSecurity;
import nx.zsanchez.nexussecurity.core.AlertSystem;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.logging.Logger;

/**
 * Blocks or allows connections based on the geographic origin of IP addresses.
 * Uses ip-api.com for country resolution with local caching.
 * Supports both blacklist mode (block listed countries) and whitelist mode (allow only listed countries).
 */
public class GeoBlocker {

    private final NexusSecurity plugin;
    private final Logger logger;
    private final AlertSystem alertSystem;

    private boolean enabled;
    private boolean whitelistMode; // true = whitelist, false = blacklist
    private Set<String> countries;
    /** Local cache: IP → country code. No TTL (country rarely changes). Bounded by LRU. */
    private final Map<String, String> countryCache = Collections.synchronizedMap(
            new LinkedHashMap<>(1000, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, String> eldest) {
                    return size() > 10000;
                }
            }
    );

    /**
     * Creates the geo-blocker.
     *
     * @param plugin      Main plugin instance
     * @param alertSystem Alert system for geo-block events
     */
    public GeoBlocker(NexusSecurity plugin, AlertSystem alertSystem) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
        this.alertSystem = alertSystem;
        loadConfig();
    }

    /**
     * Loads geo-blocking configuration.
     */
    public void loadConfig() {
        this.enabled = plugin.getConfig().getBoolean("modules.shield.geo-blocking.enabled", false);
        String mode = plugin.getConfig().getString("modules.shield.geo-blocking.mode", "blacklist");
        this.whitelistMode = "whitelist".equalsIgnoreCase(mode);
        List<String> countryList = plugin.getConfig().getStringList("modules.shield.geo-blocking.countries");
        this.countries = new HashSet<>(countryList.stream().map(String::toUpperCase).toList());
    }

    /**
     * Checks if an IP should be geo-blocked.
     * Performs async-safe country lookup with caching.
     * Must be called from an async thread.
     *
     * @param ip IP address to check
     * @return true if the connection should be blocked
     */
    public boolean isBlocked(String ip) {
        if (!enabled || countries.isEmpty()) return false;

        String countryCode = getCountryCode(ip);
        if (countryCode == null || countryCode.isEmpty()) return false;

        boolean inList = countries.contains(countryCode.toUpperCase());

        // Whitelist mode: block if NOT in list. Blacklist mode: block if IN list.
        boolean blocked = whitelistMode ? !inList : inList;

        if (blocked) {
            alertSystem.info("Shield", ip, "Geo-blocked connection from country: " + countryCode +
                    " (mode: " + (whitelistMode ? "whitelist" : "blacklist") + ")");
        }

        return blocked;
    }

    /**
     * Returns the ISO-3166 country code for an IP address.
     * Checks cache first; queries ip-api.com as fallback.
     *
     * @param ip IP to resolve
     * @return Two-letter country code, or null if unavailable
     */
    private String getCountryCode(String ip) {
        String cached = countryCache.get(ip);
        if (cached != null) return cached;

        try {
            String urlStr = "http://ip-api.com/json/" + ip + "?fields=countryCode";
            URL url = new URI(urlStr).toURL();
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(3000);
            conn.setReadTimeout(3000);
            conn.setRequestMethod("GET");
            conn.setRequestProperty("User-Agent", "NexusSecurity/1.0");

            if (conn.getResponseCode() == 200) {
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                    StringBuilder sb = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) sb.append(line);
                    String response = sb.toString();
                    // Parse countryCode from JSON: {"countryCode":"ES"}
                    int idx = response.indexOf("\"countryCode\":\"");
                    if (idx >= 0) {
                        String code = response.substring(idx + 15, idx + 17).toUpperCase();
                        countryCache.put(ip, code);
                        return code;
                    }
                }
            }
        } catch (Exception e) {
            logger.fine("[GeoBlocker] Country lookup failed for " + ip + ": " + e.getMessage());
        }
        return null;
    }

    /** @return Whether geo-blocking is enabled */
    public boolean isEnabled() { return enabled; }
}
