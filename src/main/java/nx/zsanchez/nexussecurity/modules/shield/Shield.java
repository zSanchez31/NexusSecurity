package nx.zsanchez.nexussecurity.modules.shield;

import nx.zsanchez.nexussecurity.NexusSecurity;
import nx.zsanchez.nexussecurity.core.*;
import nx.zsanchez.nexussecurity.util.MessageFormatter;
import org.bukkit.entity.Player;

import java.util.*;
import java.util.logging.Logger;

/**
 * Module 1: Shield — Firewall and Perimeter Protection.
 * Orchestrates all perimeter defense subsystems: AntiVPN, IP Reputation,
 * Geo-blocking, and Rate Limiting. Acts as the primary entry point for all
 * connection-level security checks.
 *
 * <p>All blocking decisions are made asynchronously before the player joins the server.
 * Players with the {@code nexussecurity.bypass} permission are exempt from all checks.</p>
 */
public class Shield implements nx.zsanchez.nexussecurity.core.SecurityModule {

    private final NexusSecurity plugin;
    private final Logger logger;
    private final AlertSystem alertSystem;
    private final EventBus eventBus;
    private final ThreadPoolManager threadPoolManager;

    private AntiVPN antiVPN;
    private IpReputationService ipReputationService;
    private GeoBlocker geoBlocker;
    private RateLimiter rateLimiter;

    private boolean enabled = false;
    private List<String> whitelist;
    private List<String> blacklist;

    // Stats counters
    private volatile long connectionsChecked = 0;
    private volatile long connectionsBlocked = 0;

    /**
     * Creates the Shield module and all its subsystems.
     *
     * @param plugin            Main plugin instance
     * @param cacheManager      Cache for IP lookups
     * @param databaseManager   Database for persistent blacklist/logs
     * @param alertSystem       Alert system for security events
     * @param eventBus          Internal event bus
     * @param threadPoolManager Thread pool for async operations
     */
    public Shield(NexusSecurity plugin, CacheManager cacheManager, DatabaseManager databaseManager,
                  AlertSystem alertSystem, EventBus eventBus, ThreadPoolManager threadPoolManager) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
        this.alertSystem = alertSystem;
        this.eventBus = eventBus;
        this.threadPoolManager = threadPoolManager;

        this.antiVPN = new AntiVPN(plugin, cacheManager, alertSystem, eventBus);
        this.ipReputationService = new IpReputationService(plugin, cacheManager, databaseManager, alertSystem);
        this.geoBlocker = new GeoBlocker(plugin, alertSystem);
        this.rateLimiter = new RateLimiter(plugin, alertSystem, databaseManager);
    }

    @Override
    public String getName() { return "Shield"; }

    @Override
    public String getDescription() { return "Firewall and perimeter protection (AntiVPN, IP Reputation, Geo-blocking, Rate Limiting)"; }

    @Override
    public void enable() {
        if (enabled) return;
        loadConfig();
        enabled = true;
        logger.info("[Shield] Module enabled. AntiVPN=" + antiVPN.isEnabled() +
                ", GeoBlock=" + geoBlocker.isEnabled() +
                ", RateLimit=" + rateLimiter.isEnabled());
    }

    @Override
    public void disable() {
        if (!enabled) return;
        rateLimiter.clear();
        enabled = false;
        logger.info("[Shield] Module disabled.");
    }

    @Override
    public boolean isEnabled() { return enabled; }

    /**
     * Loads Shield configuration from config.yml.
     */
    private void loadConfig() {
        this.whitelist = plugin.getConfig().getStringList("modules.shield.whitelist");
        this.blacklist = plugin.getConfig().getStringList("modules.shield.blacklist");
        antiVPN.loadConfig();
        ipReputationService.loadConfig();
        geoBlocker.loadConfig();
        rateLimiter.loadConfig();
    }

    /**
     * Performs all connection checks for a connecting player.
     * This method performs network I/O and MUST be called from an async thread.
     * Returns a {@link ConnectionCheckResult} with block decision and reason.
     *
     * @param player Player attempting to connect (may be null during pre-login)
     * @param ip     Player's IP address
     * @return Check result with allow/block decision
     */
    public ConnectionCheckResult checkConnection(Player player, String ip) {
        if (!enabled) return ConnectionCheckResult.allow();
        if (player != null && player.hasPermission("nexussecurity.bypass")) return ConnectionCheckResult.allow();

        connectionsChecked++;

        // 1. Whitelist check (always pass)
        if (whitelist.contains(ip)) return ConnectionCheckResult.allow();

        // 2. Manual blacklist check
        if (blacklist.contains(ip)) {
            connectionsBlocked++;
            return ConnectionCheckResult.block("IP en lista negra manual");
        }

        // 3. Rate limit check
        if (rateLimiter.shouldLimit(ip)) {
            connectionsBlocked++;
            return ConnectionCheckResult.block("Demasiadas conexiones (rate limit)");
        }

        // 4. IP Reputation check
        if (ipReputationService.shouldBlock(ip)) {
            connectionsBlocked++;
            return ConnectionCheckResult.block("IP con mala reputación detectada");
        }

        // 5. Geo-block check
        if (geoBlocker.isBlocked(ip)) {
            connectionsBlocked++;
            return ConnectionCheckResult.block("Conexión bloqueada por región geográfica");
        }

        // 6. AntiVPN check
        if (antiVPN.isVpn(ip)) {
            connectionsBlocked++;
            return ConnectionCheckResult.block(antiVPN.getKickMessage());
        }

        return ConnectionCheckResult.allow();
    }

    @Override
    public String getStatusSummary() {
        return String.format("&aACTIVO &7| Checked: &f%d &7| Blocked: &c%d &7| RateBanned: &e%d",
                connectionsChecked, connectionsBlocked, rateLimiter.getBannedCount());
    }

    /**
     * Reloads all Shield subsystem configurations.
     * Can be called without disabling/re-enabling the module.
     */
    public void reload() {
        loadConfig();
        logger.info("[Shield] Configuration reloaded.");
    }

    // ============================================================
    // ACCESSORS for subcommands and listeners
    // ============================================================

    /** @return The AntiVPN subsystem */
    public AntiVPN getAntiVPN() { return antiVPN; }

    /** @return The IP reputation service */
    public IpReputationService getIpReputationService() { return ipReputationService; }

    /** @return The geo-blocker */
    public GeoBlocker getGeoBlocker() { return geoBlocker; }

    /** @return The rate limiter */
    public RateLimiter getRateLimiter() { return rateLimiter; }

    /** @return Total connections checked since module enabled */
    public long getConnectionsChecked() { return connectionsChecked; }

    /** @return Total connections blocked since module enabled */
    public long getConnectionsBlocked() { return connectionsBlocked; }

    // ============================================================
    // INNER: ConnectionCheckResult
    // ============================================================

    /**
     * Result of a {@link Shield#checkConnection} call.
     */
    public record ConnectionCheckResult(boolean allowed, String blockReason) {

        /** Creates an allow result. */
        public static ConnectionCheckResult allow() {
            return new ConnectionCheckResult(true, null);
        }

        /** Creates a block result with a reason. */
        public static ConnectionCheckResult block(String reason) {
            return new ConnectionCheckResult(false, reason);
        }

        /** @return Whether the connection is blocked */
        public boolean isBlocked() { return !allowed; }
    }
}
