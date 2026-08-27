package nx.zsanchez.nexussecurity.core;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import nx.zsanchez.nexussecurity.NexusSecurity;

import java.util.concurrent.TimeUnit;
import java.util.function.Function;

/**
 * Centralized cache manager using Caffeine for high-performance, in-memory caching.
 * All NexusSecurity modules share these caches to avoid redundant computations
 * (IP lookups, file hashes, threat scores, etc.).
 *
 * <p>Cache strategies used:</p>
 * <ul>
 *   <li><b>IP Reputation Cache</b>: TTL-based (configurable), LRU eviction, bounded size</li>
 *   <li><b>File Hash Cache</b>: TTL-based for integrity checks</li>
 *   <li><b>Threat Score Cache</b>: Short TTL for dynamic threat intelligence</li>
 *   <li><b>VPN Detection Cache</b>: Medium TTL to avoid repeated API calls</li>
 *   <li><b>General Cache</b>: Generic TTL-based cache for module-specific data</li>
 * </ul>
 */
public class CacheManager {

    /** Cache for IP reputation scores (key: IP string, value: score 0-100) */
    private final Cache<String, Integer> ipReputationCache;

    /** Cache for VPN/proxy detection results (key: IP string, value: is-vpn boolean) */
    private final Cache<String, Boolean> vpnCache;

    /** Cache for file SHA-256 hashes (key: absolute file path, value: SHA-256 hex) */
    private final Cache<String, String> fileHashCache;

    /** Cache for threat intelligence scores (key: IP/domain, value: threat score 0-100) */
    private final Cache<String, Integer> threatScoreCache;

    /** General-purpose String-to-Object cache for module-specific data */
    private final Cache<String, Object> generalCache;

    /**
     * Initializes all caches with configuration from config.yml.
     *
     * @param plugin The main plugin instance
     */
    public CacheManager(NexusSecurity plugin) {
        long ipCacheTtl = plugin.getConfig().getLong("performance.ip-cache-ttl-seconds", 1800);
        long fileHashTtl = plugin.getConfig().getLong("performance.file-hash-cache-ttl-seconds", 300);
        long ipCacheMax  = plugin.getConfig().getLong("performance.ip-cache-max-size", 10000);

        this.ipReputationCache = Caffeine.newBuilder()
                .maximumSize(ipCacheMax)
                .expireAfterWrite(ipCacheTtl, TimeUnit.SECONDS)
                .recordStats()
                .build();

        this.vpnCache = Caffeine.newBuilder()
                .maximumSize(ipCacheMax)
                .expireAfterWrite(ipCacheTtl, TimeUnit.SECONDS)
                .recordStats()
                .build();

        this.fileHashCache = Caffeine.newBuilder()
                .maximumSize(5000)
                .expireAfterWrite(fileHashTtl, TimeUnit.SECONDS)
                .recordStats()
                .build();

        this.threatScoreCache = Caffeine.newBuilder()
                .maximumSize(ipCacheMax)
                .expireAfterWrite(3600, TimeUnit.SECONDS) // 1 hour TTL
                .recordStats()
                .build();

        this.generalCache = Caffeine.newBuilder()
                .maximumSize(50000)
                .expireAfterWrite(600, TimeUnit.SECONDS) // 10 min TTL
                .recordStats()
                .build();

        plugin.getLogger().info("[CacheManager] Initialized all caches (IP TTL: " + ipCacheTtl + "s, maxSize: " + ipCacheMax + ").");
    }

    // ============================================================
    // IP REPUTATION CACHE
    // ============================================================

    /**
     * Returns the cached reputation score for an IP, or null if not cached.
     *
     * @param ip IP address string
     * @return Score 0-100, or null if not in cache
     */
    public Integer getIpReputation(String ip) {
        return ipReputationCache.getIfPresent(ip);
    }

    /**
     * Stores an IP reputation score in the cache.
     *
     * @param ip    IP address string
     * @param score Reputation score 0-100 (100 = most malicious)
     */
    public void putIpReputation(String ip, int score) {
        ipReputationCache.put(ip, score);
    }

    /**
     * Gets or computes the reputation score for an IP.
     *
     * @param ip      IP address string
     * @param loader  Function to compute the score if not cached
     * @return Cached or freshly computed score
     */
    public Integer getOrComputeIpReputation(String ip, Function<String, Integer> loader) {
        return ipReputationCache.get(ip, loader);
    }

    // ============================================================
    // VPN DETECTION CACHE
    // ============================================================

    /**
     * Returns the cached VPN detection result for an IP, or null if not cached.
     *
     * @param ip IP address string
     * @return true if VPN detected, false if clean, null if not cached
     */
    public Boolean getVpnResult(String ip) {
        return vpnCache.getIfPresent(ip);
    }

    /**
     * Stores a VPN detection result in the cache.
     *
     * @param ip    IP address string
     * @param isVpn Whether the IP is a VPN/proxy
     */
    public void putVpnResult(String ip, boolean isVpn) {
        vpnCache.put(ip, isVpn);
    }

    // ============================================================
    // FILE HASH CACHE
    // ============================================================

    /**
     * Returns the cached SHA-256 hash for a file path, or null if not cached.
     *
     * @param absolutePath Absolute file path
     * @return SHA-256 hex string, or null if not cached
     */
    public String getFileHash(String absolutePath) {
        return fileHashCache.getIfPresent(absolutePath);
    }

    /**
     * Stores a file hash in the cache.
     *
     * @param absolutePath Absolute file path
     * @param hash         SHA-256 hex string
     */
    public void putFileHash(String absolutePath, String hash) {
        fileHashCache.put(absolutePath, hash);
    }

    // ============================================================
    // THREAT SCORE CACHE
    // ============================================================

    /**
     * Returns the cached threat score for an IP or domain.
     *
     * @param indicator IP or domain string
     * @return Threat score 0-100, or null if not cached
     */
    public Integer getThreatScore(String indicator) {
        return threatScoreCache.getIfPresent(indicator);
    }

    /**
     * Stores a threat score in the cache.
     *
     * @param indicator IP or domain string
     * @param score     Threat score 0-100
     */
    public void putThreatScore(String indicator, int score) {
        threatScoreCache.put(indicator, score);
    }

    // ============================================================
    // GENERAL PURPOSE CACHE
    // ============================================================

    /**
     * Returns a cached value from the general cache.
     *
     * @param key Cache key
     * @return Cached value, or null if not present
     */
    public Object get(String key) {
        return generalCache.getIfPresent(key);
    }

    /**
     * Stores a value in the general cache.
     *
     * @param key   Cache key
     * @param value Value to cache
     */
    public void put(String key, Object value) {
        generalCache.put(key, value);
    }

    /**
     * Removes an entry from the general cache.
     *
     * @param key Cache key to invalidate
     */
    public void invalidate(String key) {
        generalCache.invalidate(key);
    }

    // ============================================================
    // STATS
    // ============================================================

    /** @return Current size of the file hash cache */
    public long getFileHashCacheSize() { return fileHashCache.estimatedSize(); }

    /** @return Current size of the threat score cache */
    public long getThreatScoreCacheSize() { return threatScoreCache.estimatedSize(); }

    /** @return Current size of the general cache */
    public long getGeneralCacheSize() { return generalCache.estimatedSize(); }

    /**
     * Returns a human-readable summary of all cache statistics.
     *
     * @return Cache stats string
     */
    public String getStats() {
        return String.format(
                "IP(%d) VPN(%d) Hash(%d) Threat(%d) General(%d)",
                ipReputationCache.estimatedSize(),
                vpnCache.estimatedSize(),
                fileHashCache.estimatedSize(),
                threatScoreCache.estimatedSize(),
                generalCache.estimatedSize()
        );
    }

    /**
     * Clears all caches. Used on plugin reload.
     */
    public void invalidateAll() {
        ipReputationCache.invalidateAll();
        vpnCache.invalidateAll();
        fileHashCache.invalidateAll();
        threatScoreCache.invalidateAll();
        generalCache.invalidateAll();
    }
}
