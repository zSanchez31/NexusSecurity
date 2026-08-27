package nx.zsanchez.nexussecurity.modules.threatintel;

import nx.zsanchez.nexussecurity.NexusSecurity;
import nx.zsanchez.nexussecurity.core.AlertSystem;
import nx.zsanchez.nexussecurity.core.CacheManager;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

/**
 * Synchronizes global threat feeds (malicious IPs and domains) from central intelligence servers.
 */
public class ThreatFeedSync {

    private final NexusSecurity plugin;
    private final Logger logger;
    private final AlertSystem alertSystem;
    private final CacheManager cacheManager;

    private List<String> feedUrls;
    private int confidenceThreshold;

    public ThreatFeedSync(NexusSecurity plugin, AlertSystem alertSystem, CacheManager cacheManager) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
        this.alertSystem = alertSystem;
        this.cacheManager = cacheManager;
        loadConfig();
    }

    public void loadConfig() {
        this.feedUrls = plugin.getConfig().getStringList("modules.threat-intelligence.feeds");
        this.confidenceThreshold = plugin.getConfig().getInt("modules.threat-intelligence.confidence-threshold", 80);
    }

    /**
     * Downloads and parses threat feeds asynchronously.
     * Indicators are persisted to the database (threat_indicators) and cached in memory
     * so that {@code IpReputationService} can enforce preventive blocking.
     */
    public void syncFeeds() {
        if (feedUrls == null || feedUrls.isEmpty()) return;

        int indicatorsCount = 0;
        long expiry = System.currentTimeMillis() + TimeUnit.DAYS.toMillis(30);
        for (String urlStr : feedUrls) {
            try {
                URL url = new URI(urlStr).toURL();
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("GET");
                conn.setConnectTimeout(5000);
                conn.setReadTimeout(5000);

                if (conn.getResponseCode() == 200) {
                    try (BufferedReader reader = new BufferedReader(
                            new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                        String line;
                        while ((line = reader.readLine()) != null) {
                            line = line.trim();
                            if (!line.isEmpty() && !line.startsWith("#")) {
                                cacheManager.putThreatScore(line, 90);
                                plugin.getDatabaseManager().insertThreatIndicator(
                                        line, detectType(line), 90, "THREAT-FEED", expiry,
                                        "Global threat feed indicator");
                                indicatorsCount++;
                            }
                        }
                    }
                }
            } catch (Exception e) {
                logger.fine("[ThreatIntel] Sync failed for feed " + urlStr + ": " + e.getMessage());
            }
        }
        logger.info("[ThreatIntel] Synchronized " + indicatorsCount + " global threat indicators.");
    }

    /**
     * Best-effort classification of a feed line as IP, URL, or DOMAIN.
     *
     * @param indicator The raw indicator string
     * @return Indicator type
     */
    private String detectType(String indicator) {
        String lower = indicator.toLowerCase();
        if (lower.matches("\\d{1,3}(\\.\\d{1,3}){3}") || lower.contains(":")) return "IP";
        if (lower.startsWith("http://") || lower.startsWith("https://")) return "URL";
        return "DOMAIN";
    }
}
