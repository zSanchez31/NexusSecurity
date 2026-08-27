package nx.zsanchez.nexussecurity.modules.shield;

import nx.zsanchez.nexussecurity.NexusSecurity;
import nx.zsanchez.nexussecurity.core.AlertSystem;
import nx.zsanchez.nexussecurity.core.DatabaseManager;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

/**
 * Implements a sliding-window rate limiter to prevent connection brute-force attacks.
 * Tracks connection attempts per IP and temporarily bans IPs exceeding the threshold.
 *
 * <p>Algorithm: Sliding window counter.
 * Each IP has an attempt count and a window start timestamp.
 * When the window expires, the count resets. If count exceeds maxAttempts, the IP is banned.</p>
 *
 * <p>Memory management: Expired entries are lazily evicted on access.</p>
 */
public class RateLimiter {

    /** Tracks connection attempts per IP. */
    private record AttemptRecord(long windowStart, int count) {}

    private final NexusSecurity plugin;
    private final Logger logger;
    private final AlertSystem alertSystem;
    private final DatabaseManager databaseManager;

    private int maxConnections;
    private long windowMs;
    private long banDurationMs;
    private boolean enabled;

    /** Map of IP → AttemptRecord (sliding window). */
    private final Map<String, AttemptRecord> attempts = new ConcurrentHashMap<>();
    /** Map of IP → ban expiry timestamp. */
    private final Map<String, Long> banned = new ConcurrentHashMap<>();

    /**
     * Creates the rate limiter.
     *
     * @param plugin          Main plugin instance
     * @param alertSystem     Alert system for ban events
     * @param databaseManager DB for persisting bans
     */
    public RateLimiter(NexusSecurity plugin, AlertSystem alertSystem, DatabaseManager databaseManager) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
        this.alertSystem = alertSystem;
        this.databaseManager = databaseManager;
        loadConfig();

        // Periodic eviction of expired bans / stale attempts so these maps never grow unbounded.
        plugin.getThreadPoolManager().scheduleAtFixedRate(
                "RateLimiter-Evict",
                this::evictExpired,
                60, 60, TimeUnit.SECONDS
        );
    }

    /**
     * Removes expired ban entries and stale attempt windows.
     * Bounds memory usage on long-running servers where banned IPs may never be queried again.
     */
    public void evictExpired() {
        long now = System.currentTimeMillis();
        banned.entrySet().removeIf(e -> e.getValue() <= now);
        long cutoff = now - windowMs * 2;
        attempts.entrySet().removeIf(e -> e.getValue().windowStart() < cutoff);
    }

    /**
     * Loads rate limiting configuration.
     */
    public void loadConfig() {
        this.enabled = plugin.getConfig().getBoolean("modules.shield.rate-limiting.enabled", true);
        this.maxConnections = plugin.getConfig().getInt(
                "modules.shield.rate-limiting.max-connections-per-window", 5);
        long windowSeconds = plugin.getConfig().getLong(
                "modules.shield.rate-limiting.window-seconds", 60);
        this.windowMs = TimeUnit.SECONDS.toMillis(windowSeconds);
        long banMinutes = plugin.getConfig().getLong(
                "modules.shield.rate-limiting.ban-duration-minutes", 30);
        this.banDurationMs = TimeUnit.MINUTES.toMillis(banMinutes);
    }

    /**
     * Records a connection attempt from an IP and returns whether it should be rate-limited.
     *
     * @param ip The connecting IP address
     * @return true if this IP should be blocked (rate limit exceeded or temp-banned)
     */
    public boolean shouldLimit(String ip) {
        if (!enabled) return false;

        // Check if currently banned
        Long banExpiry = banned.get(ip);
        if (banExpiry != null) {
            if (System.currentTimeMillis() < banExpiry) {
                return true; // Still banned
            } else {
                banned.remove(ip); // Ban expired
            }
        }

        long now = System.currentTimeMillis();
        AttemptRecord record = attempts.compute(ip, (k, existing) -> {
            if (existing == null || now - existing.windowStart() > windowMs) {
                // New window
                return new AttemptRecord(now, 1);
            } else {
                return new AttemptRecord(existing.windowStart(), existing.count() + 1);
            }
        });

        if (record.count() > maxConnections) {
            // Threshold exceeded — temp-ban this IP
            banned.put(ip, now + banDurationMs);
            attempts.remove(ip); // Reset counter

            alertSystem.warning("Shield", ip, "Rate limit exceeded (" + record.count() +
                    " connections in " + (windowMs / 1000) + "s window). Temp-banned for " +
                    (banDurationMs / 60000) + " minutes.");

            databaseManager.blacklistIp(ip, "Rate limit exceeded",
                    "RateLimiter", now + banDurationMs, 60);

            // Bound the attempts map if it grows unexpectedly large between eviction cycles.
            if (attempts.size() > 10000) {
                evictExpired();
            }
            return true;
        }

        return false;
    }

    /**
     * Returns whether an IP is currently rate-limited or temp-banned.
     *
     * @param ip IP to check
     * @return true if rate-limited
     */
    public boolean isBanned(String ip) {
        Long expiry = banned.get(ip);
        if (expiry == null) return false;
        if (System.currentTimeMillis() >= expiry) {
            banned.remove(ip);
            return false;
        }
        return true;
    }

    /**
     * Manually removes an IP from the rate-limit ban list.
     *
     * @param ip IP to unban
     */
    public void unban(String ip) {
        banned.remove(ip);
        attempts.remove(ip);
        logger.info("[RateLimiter] Manually unbanned IP: " + ip);
    }

    /**
     * Clears all rate-limit state. Used on plugin disable.
     */
    public void clear() {
        attempts.clear();
        banned.clear();
    }

    /** @return Whether rate limiting is enabled */
    public boolean isEnabled() { return enabled; }

    /** @return Number of currently temp-banned IPs */
    public int getBannedCount() { return banned.size(); }
}
