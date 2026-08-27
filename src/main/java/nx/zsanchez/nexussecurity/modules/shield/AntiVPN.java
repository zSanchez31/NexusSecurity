package nx.zsanchez.nexussecurity.modules.shield;

import nx.zsanchez.nexussecurity.NexusSecurity;
import nx.zsanchez.nexussecurity.core.AlertSystem;
import nx.zsanchez.nexussecurity.core.CacheManager;
import nx.zsanchez.nexussecurity.core.DatabaseManager;
import nx.zsanchez.nexussecurity.core.EventBus;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.logging.Logger;

/**
 * Detects VPN, proxy, and anonymizing tunnel connections using external API services.
 * Provides configurable sensitivity levels and caches results to minimize API calls.
 *
 * <p>Supported detection APIs:</p>
 * <ul>
 *   <li>proxycheck.io — Primary service, highly accurate</li>
 *   <li>ip-api.com — Fallback service, free tier</li>
 * </ul>
 *
 * <p>Sensitivity levels:</p>
 * <ul>
 *   <li>LOW: Only block confirmed proxies (confidence ≥ 90)</li>
 *   <li>MEDIUM: Block VPNs and proxies (confidence ≥ 70)</li>
 *   <li>HIGH: Block any anonymizing service (confidence ≥ 50)</li>
 *   <li>EXTREME: Block any proxy indicator (confidence ≥ 30)</li>
 * </ul>
 */
public class AntiVPN {

    private final NexusSecurity plugin;
    private final Logger logger;
    private final CacheManager cacheManager;
    private final AlertSystem alertSystem;
    private final EventBus eventBus;

    private boolean enabled;
    private int sensitivityThreshold;
    private String action;
    private String kickMessage;
    private boolean proxycheckEnabled;
    private String proxycheckApiKey;
    private boolean ipApiEnabled;

    /**
     * Creates AntiVPN. Config is read at construction time and on each reload.
     *
     * @param plugin       Main plugin instance
     * @param cacheManager Cache for storing VPN lookup results
     * @param alertSystem  Alert system for VPN detections
     * @param eventBus     Event bus for publishing VPN events
     */
    public AntiVPN(NexusSecurity plugin, CacheManager cacheManager,
                   AlertSystem alertSystem, EventBus eventBus) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
        this.cacheManager = cacheManager;
        this.alertSystem = alertSystem;
        this.eventBus = eventBus;
        loadConfig();
    }

    /**
     * Loads AntiVPN configuration from config.yml.
     */
    public void loadConfig() {
        this.enabled = plugin.getConfig().getBoolean("modules.shield.anti-vpn.enabled", true);
        this.action = plugin.getConfig().getString("modules.shield.anti-vpn.action", "kick");
        this.kickMessage = plugin.getConfig().getString("modules.shield.anti-vpn.kick-message",
                "&cConnections from VPNs are not allowed.");
        this.proxycheckEnabled = plugin.getConfig().getBoolean(
                "modules.shield.anti-vpn.apis.proxycheck.enabled", true);
        this.proxycheckApiKey = plugin.getConfig().getString(
                "modules.shield.anti-vpn.apis.proxycheck.api-key", "");
        this.ipApiEnabled = plugin.getConfig().getBoolean(
                "modules.shield.anti-vpn.apis.ip-api.enabled", true);

        String sensitivity = plugin.getConfig().getString(
                "modules.shield.anti-vpn.sensitivity", "medium").toLowerCase();
        this.sensitivityThreshold = switch (sensitivity) {
            case "low"     -> 90;
            case "high"    -> 50;
            case "extreme" -> 30;
            default        -> 70; // medium
        };
    }

    /**
     * Checks if an IP is a VPN or proxy.
     * This method performs network I/O and MUST be called from an async thread.
     * Results are cached to avoid redundant lookups.
     *
     * @param ip The IP address to check
     * @return true if the IP is identified as a VPN/proxy at current sensitivity
     */
    public boolean isVpn(String ip) {
        if (!enabled) return false;
        // Skip RFC1918 private addresses
        if (isPrivateIp(ip)) return false;

        // Check cache first
        Boolean cached = cacheManager.getVpnResult(ip);
        if (cached != null) return cached;

        boolean result = false;
        int confidence = 0;

        // Try proxycheck.io first (primary)
        if (proxycheckEnabled) {
            try {
                confidence = checkProxycheck(ip);
                result = confidence >= sensitivityThreshold;
            } catch (Exception e) {
                logger.fine("[AntiVPN] proxycheck.io failed for " + ip + ": " + e.getMessage());
            }
        }

        // Fallback to ip-api.com if proxycheck failed or not enabled
        if (!result && confidence == 0 && ipApiEnabled) {
            try {
                result = checkIpApi(ip);
                confidence = result ? 85 : 0;
            } catch (Exception e) {
                logger.fine("[AntiVPN] ip-api.com failed for " + ip + ": " + e.getMessage());
            }
        }

        // Cache result
        cacheManager.putVpnResult(ip, result);

        if (result) {
            alertSystem.warning("AntiVPN", ip,
                    "VPN/Proxy detected (confidence: " + confidence + "%, sensitivity threshold: " + sensitivityThreshold + "%)");
            eventBus.publish(EventBus.EVENT_VPN_DETECTED, Map.of("ip", ip, "confidence", confidence));
        }

        return result;
    }

    /**
     * Queries proxycheck.io API for VPN/proxy detection.
     *
     * @param ip IP to check
     * @return Confidence percentage (0-100) that this is a proxy/VPN
     * @throws IOException on network error
     */
    private int checkProxycheck(String ip) throws IOException {
        String urlStr = "https://proxycheck.io/v2/" + ip + "?vpn=1&asn=1&risk=1&port=1&seen=1";
        if (!proxycheckApiKey.isBlank()) {
            urlStr += "&key=" + proxycheckApiKey;
        }

        String response = httpGet(urlStr, 5000);
        if (response == null) return 0;

        // Parse simple JSON response from proxycheck
        // {"status":"ok", "IP": {"proxy":"yes","type":"VPN","risk":87}}
        boolean isProxy = response.contains("\"proxy\":\"yes\"") ||
                response.contains("\"proxy\": \"yes\"");

        if (isProxy) {
            // Extract risk score if available
            int riskIdx = response.indexOf("\"risk\":");
            if (riskIdx >= 0) {
                try {
                    String riskPart = response.substring(riskIdx + 7).replaceAll("[^0-9].*", "").trim();
                    return Integer.parseInt(riskPart);
                } catch (NumberFormatException ignored) {}
            }
            return 85; // Default confidence if proxy detected but no risk score
        }
        return 0;
    }

    /**
     * Queries ip-api.com for proxy/VPN detection.
     *
     * @param ip IP to check
     * @return true if identified as proxy
     * @throws IOException on network error
     */
    private boolean checkIpApi(String ip) throws IOException {
        String urlStr = "http://ip-api.com/json/" + ip + "?fields=proxy,hosting,mobile";
        String response = httpGet(urlStr, 5000);
        if (response == null) return false;
        return response.contains("\"proxy\":true") ||
                response.contains("\"proxy\": true") ||
                response.contains("\"hosting\":true") ||
                response.contains("\"hosting\": true");
    }

    /**
     * Performs a simple HTTP GET request and returns the response body.
     *
     * @param urlStr         URL to fetch
     * @param timeoutMs      Connection and read timeout in milliseconds
     * @return Response body, or null on error
     */
    private String httpGet(String urlStr, int timeoutMs) {
        try {
            URL url = new URI(urlStr).toURL();
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(timeoutMs);
            conn.setReadTimeout(timeoutMs);
            conn.setRequestProperty("User-Agent", "NexusSecurity/1.0");

            if (conn.getResponseCode() == 200) {
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                    StringBuilder sb = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) sb.append(line);
                    return sb.toString();
                }
            }
        } catch (Exception e) {
            logger.fine("[AntiVPN] HTTP GET failed for " + urlStr + ": " + e.getMessage());
        }
        return null;
    }

    /**
     * Checks if an IP is a private/local address that should never be VPN-checked.
     *
     * @param ip IP address string
     * @return true if private
     */
    private boolean isPrivateIp(String ip) {
        return ip.startsWith("10.") || ip.startsWith("192.168.") ||
                ip.startsWith("172.16.") || ip.startsWith("172.17.") ||
                ip.startsWith("172.18.") || ip.startsWith("172.19.") ||
                ip.startsWith("172.2")   || ip.startsWith("172.3") ||
                ip.equals("127.0.0.1")   || ip.equals("::1") ||
                ip.equals("localhost");
    }

    /**
     * Returns the configured kick message for VPN-detected players.
     *
     * @return Kick message with color codes
     */
    public String getKickMessage() { return kickMessage; }

    /**
     * Returns the configured action for VPN detections.
     *
     * @return Action string ("kick", "ban", "flag")
     */
    public String getAction() { return action; }

    /** @return Whether AntiVPN is enabled */
    public boolean isEnabled() { return enabled; }
}
