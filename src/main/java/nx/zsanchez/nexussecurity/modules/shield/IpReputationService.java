package nx.zsanchez.nexussecurity.modules.shield;

import nx.zsanchez.nexussecurity.NexusSecurity;
import nx.zsanchez.nexussecurity.core.AlertSystem;
import nx.zsanchez.nexussecurity.core.CacheManager;
import nx.zsanchez.nexussecurity.core.DatabaseManager;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.logging.Logger;

/**
 * Checks IP addresses against reputation databases to detect known malicious IPs.
 * Combines local database blacklist with optional external AbuseIPDB API checks.
 * Results are cached via {@link CacheManager} to minimize latency and API usage.
 *
 * <p>Reputation Score: 0-100 (0 = clean, 100 = maximally malicious).
 * Blocking threshold is configurable in config.yml.</p>
 */
public class IpReputationService {

    private final NexusSecurity plugin;
    private final Logger logger;
    private final CacheManager cacheManager;
    private final DatabaseManager databaseManager;
    private final AlertSystem alertSystem;

    private int blockThreshold;
    private boolean abuseIpDbEnabled;
    private String abuseIpDbKey;

    /**
     * Creates the IP reputation service.
     *
     * @param plugin          Main plugin instance
     * @param cacheManager    Cache for reputation scores
     * @param databaseManager DB for persistent blacklist
     * @param alertSystem     Alert system for flagging malicious IPs
     */
    public IpReputationService(NexusSecurity plugin, CacheManager cacheManager,
                               DatabaseManager databaseManager, AlertSystem alertSystem) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
        this.cacheManager = cacheManager;
        this.databaseManager = databaseManager;
        this.alertSystem = alertSystem;
        loadConfig();
    }

    /**
     * Loads reputation service configuration.
     */
    public void loadConfig() {
        this.blockThreshold = plugin.getConfig().getInt(
                "modules.shield.ip-reputation.block-threshold", 75);
        this.abuseIpDbEnabled = plugin.getConfig().getBoolean(
                "modules.shield.ip-reputation.abuseipdb.enabled", false);
        this.abuseIpDbKey = plugin.getConfig().getString(
                "modules.shield.ip-reputation.abuseipdb.api-key", "");
    }

    /**
     * Returns the reputation score for an IP (0-100).
     * Checks cache, then local DB blacklist, then optional AbuseIPDB API.
     * This method performs I/O and must be called from an async thread.
     *
     * @param ip The IP address to check
     * @return Reputation score (0=clean, 100=maximally malicious)
     */
    public int getReputationScore(String ip) {
        // 1. Check cache
        Integer cached = cacheManager.getIpReputation(ip);
        if (cached != null) return cached;

        int score = 0;

        // 2. Check local DB blacklist
        if (databaseManager.isBlacklisted(ip)) {
            score = 100;
        } else {
            // 3. Check synced global threat indicators (Threat Intelligence feed)
            Integer threatScore = databaseManager.getThreatIndicatorScore(ip);
            if (threatScore != null) {
                score = Math.max(score, threatScore);
            }

            // 4. Check in-memory threat cache (recently synced indicators)
            Integer cachedThreat = cacheManager.getThreatScore(ip);
            if (cachedThreat != null) {
                score = Math.max(score, cachedThreat);
            }
        }

        // 5. Check AbuseIPDB if configured
        if (abuseIpDbEnabled && !abuseIpDbKey.isBlank()) {
            score = Math.max(score, checkAbuseIpDb(ip));
        }

        cacheManager.putIpReputation(ip, score);

        if (score >= blockThreshold) {
            alertSystem.warning("Shield", ip,
                    "Malicious IP reputation score: " + score + "/100 (threshold: " + blockThreshold + ")");
            plugin.getEventBus().publish(
                    nx.zsanchez.nexussecurity.core.EventBus.EVENT_THREAT_DETECTED,
                    java.util.Map.of("ip", ip, "score", score));
        }

        return score;
    }

    /**
     * Returns whether an IP should be blocked based on its reputation score.
     *
     * @param ip The IP address to evaluate
     * @return true if the IP should be blocked
     */
    public boolean shouldBlock(String ip) {
        return getReputationScore(ip) >= blockThreshold;
    }

    /**
     * Queries AbuseIPDB for the IP's abuse confidence score.
     *
     * @param ip IP to check
     * @return Abuse confidence score 0-100
     */
    private int checkAbuseIpDb(String ip) {
        try {
            String urlStr = "https://api.abuseipdb.com/api/v2/check?ipAddress=" +
                    URLEncoder.encode(ip, StandardCharsets.UTF_8) + "&maxAgeInDays=30";
            URL url = new URI(urlStr).toURL();
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);
            conn.setRequestProperty("Key", abuseIpDbKey);
            conn.setRequestProperty("Accept", "application/json");

            if (conn.getResponseCode() == 200) {
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                    StringBuilder sb = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) sb.append(line);
                    String response = sb.toString();
                    // Parse abuseConfidenceScore from JSON
                    int idx = response.indexOf("\"abuseConfidenceScore\":");
                    if (idx >= 0) {
                        String scorePart = response.substring(idx + 23).replaceAll("[^0-9].*", "").trim();
                        return Integer.parseInt(scorePart);
                    }
                }
            }
        } catch (Exception e) {
            logger.fine("[IpReputation] AbuseIPDB check failed for " + ip + ": " + e.getMessage());
        }
        return 0;
    }

    /**
     * Manually adds an IP to the permanent blacklist.
     *
     * @param ip     IP to blacklist
     * @param reason Reason for blacklisting
     */
    public void manualBlacklist(String ip, String reason) {
        databaseManager.blacklistIp(ip, reason, "MANUAL", -1, 100);
        cacheManager.putIpReputation(ip, 100);
        logger.info("[IpReputation] Manually blacklisted IP: " + ip + " (" + reason + ")");
    }
}
