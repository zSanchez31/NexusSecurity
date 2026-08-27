package nx.zsanchez.nexussecurity.api;

import nx.zsanchez.nexussecurity.NexusSecurity;
import nx.zsanchez.nexussecurity.api.model.SubscriptionResponse;
import nx.zsanchez.nexussecurity.core.EventBus;
import nx.zsanchez.nexussecurity.core.ModuleManager;
import nx.zsanchez.nexussecurity.core.ThreadPoolManager;
import nx.zsanchez.nexussecurity.util.MessageFormatter;
import nx.zsanchez.nexussecurity.util.TimeUtil;
import org.bukkit.Bukkit;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.configuration.file.YamlConfiguration;

import java.io.File;
import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

/**
 * Manages the complete lifecycle of the NexusSecurity subscription.
 * Handles initial validation, periodic re-validation, grace period logic,
 * and expiry warnings. Coordinates module enable/disable based on subscription state.
 *
 * <p>Subscription lifecycle:</p>
 * <ol>
 *   <li>On plugin start: validate immediately (async)</li>
 *   <li>If valid: enable all modules, schedule re-validation every 24h</li>
 *   <li>If API unreachable: enter grace period (configurable, default 72h)</li>
 *   <li>If expired/invalid: disable all modules, run in limited mode</li>
 *   <li>7 days before expiry: warn the server owner in console and in-game</li>
 * </ol>
 */
public class SubscriptionManager {

    /** Filename for persisting subscription state across restarts. */
    private static final String CACHE_FILE = "subscription-cache.yml";

    private final NexusSecurity plugin;
    private final Logger logger;
    private final ApiValidator apiValidator;
    private final ModuleManager moduleManager;
    private final EventBus eventBus;
    private final ThreadPoolManager threadPoolManager;

    private SubscriptionResponse currentSubscription;
    private boolean subscriptionActive = false;
    private long graceStartTime = -1;
    private long gracePeriodMs;
    private long revalidationIntervalHours;

    private ScheduledFuture<?> revalidationTask;
    private ScheduledFuture<?> expiryWarningTask;

    /**
     * Creates the subscription manager.
     *
     * @param plugin            Main plugin instance
     * @param apiValidator      API validator for HTTP calls
     * @param moduleManager     Module manager to enable/disable modules
     * @param eventBus          Event bus for publishing subscription events
     * @param threadPoolManager Thread pool for async operations
     */
    public SubscriptionManager(NexusSecurity plugin, ApiValidator apiValidator,
                               ModuleManager moduleManager, EventBus eventBus,
                               ThreadPoolManager threadPoolManager) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
        this.apiValidator = apiValidator;
        this.moduleManager = moduleManager;
        this.eventBus = eventBus;
        this.threadPoolManager = threadPoolManager;
        this.gracePeriodMs = TimeUnit.HOURS.toMillis(
                plugin.getConfig().getLong("api.grace-period-hours", 72));
        this.revalidationIntervalHours = plugin.getConfig().getLong(
                "api.revalidation-interval-hours", 24);
    }

    /**
     * Initiates async subscription validation on plugin start.
     * Loads cached state first so the server can start immediately.
     */
    public void initializeAsync() {
        // Load cached state for fast startup
        SubscriptionResponse cached = loadCachedSubscription();

        if (cached != null && cached.isValid()) {
            long remaining = cached.getExpiresAt() - System.currentTimeMillis();
            if (remaining > 0) {
                logger.info("[Subscription] Using cached subscription (expires in " +
                        TimeUtil.formatDuration(remaining) + "). Enabling modules temporarily...");
                activateModules(cached);
            }
        } else {
            logger.info("[Subscription] No valid cache found. Plugin starting in LIMITED mode pending validation.");
        }

        // Validate in background
        threadPoolManager.submit("SubscriptionValidation", this::performValidation);
    }

    /**
     * Performs the actual API validation and reacts to the result.
     * This method is called from async threads.
     */
    private void performValidation() {
        String apiKey = plugin.getConfig().getString("api.key", "");
        logger.info("[Subscription] Validating API key...");

        SubscriptionResponse response = apiValidator.validate(apiKey);
        this.currentSubscription = response;

        // Switch back to main thread for Bukkit operations
        Bukkit.getScheduler().runTask(plugin, () -> handleValidationResult(response));
    }

    /**
     * Handles the validation result on the main thread.
     *
     * @param response The API response
     */
    private void handleValidationResult(SubscriptionResponse response) {
        if (response.isValid()) {
            graceStartTime = -1;
            subscriptionActive = true;

            if (!moduleManager.isModuleActive("shield")) {
                // Modules not yet active — enable them now
                activateModules(response);
            }

            saveSubscriptionCache(response);
            scheduleRevalidation();
            scheduleExpiryWarning(response);

            logger.info("[Subscription] ✅ ACTIVE — Plan: " + response.getPlan() +
                    " | Expires: " + TimeUtil.format(response.getExpiresAt()) +
                    " | Expires in: " + TimeUtil.timeUntil(response.getExpiresAt()));

            eventBus.publish(EventBus.EVENT_SUBSCRIPTION_OK, Map.of(
                    "expiresAt", response.getExpiresAt(),
                    "plan", response.getPlan()
            ));

        } else {
            // Check if we can use grace period
            if (isGracePeriodActive()) {
                logger.warning("[Subscription] API validation failed. Grace period active (" +
                        TimeUtil.timeUntil(graceStartTime + gracePeriodMs) + " remaining). Modules stay active.");
                // Keep modules running during grace period
            } else {
                // Start grace period if not already started
                if (graceStartTime < 0 && isNetworkError(response)) {
                    graceStartTime = System.currentTimeMillis();
                    logger.warning("[Subscription] API server unreachable. Starting " +
                            TimeUtil.formatDuration(gracePeriodMs) + " grace period.");
                    scheduleGraceExpiry();
                } else {
                    // Invalid key or subscription truly expired
                    deactivateModules();
                    logger.severe("[Subscription] ❌ INVALID — " + response.getMessage() +
                            ". Plugin running in LIMITED mode (logs only).");
                    eventBus.publish(EventBus.EVENT_SUBSCRIPTION_FAIL);
                }
            }
        }
    }

    /**
     * Activates all modules after successful validation.
     *
     * @param response The validated subscription response
     */
    private void activateModules(SubscriptionResponse response) {
        subscriptionActive = true;
        // Update server ID if provided by API
        if (response.getServerId() != null) {
            plugin.setServerId(response.getServerId());
        }
        moduleManager.enableAll();
        logger.info("[Subscription] All security modules activated.");
    }

    /**
     * Deactivates all modules on subscription failure.
     */
    private void deactivateModules() {
        subscriptionActive = false;
        moduleManager.disableAll();
        logger.warning("[Subscription] All security modules deactivated. LIMITED mode active.");
    }

    /**
     * Schedules periodic re-validation.
     */
    private void scheduleRevalidation() {
        if (revalidationTask != null && !revalidationTask.isCancelled()) {
            revalidationTask.cancel(false);
        }
        revalidationTask = threadPoolManager.scheduleAtFixedRate(
                "SubscriptionRevalidation",
                this::performValidation,
                revalidationIntervalHours,
                revalidationIntervalHours,
                TimeUnit.HOURS
        );
        logger.fine("[Subscription] Re-validation scheduled every " + revalidationIntervalHours + " hours.");
    }

    /**
     * Schedules a warning 7 days before subscription expiry.
     *
     * @param response The current subscription response
     */
    private void scheduleExpiryWarning(SubscriptionResponse response) {
        if (expiryWarningTask != null) expiryWarningTask.cancel(false);

        long expiryMs = response.getExpiresAt();
        long warningAt = expiryMs - TimeUnit.DAYS.toMillis(7);
        long delayMs = warningAt - System.currentTimeMillis();

        if (delayMs > 0) {
            expiryWarningTask = threadPoolManager.schedule(
                    "SubscriptionExpiryWarning",
                    () -> Bukkit.getScheduler().runTask(plugin, this::sendExpiryWarning),
                    delayMs,
                    TimeUnit.MILLISECONDS
            );
        }
    }

    /**
     * Sends expiry warning to console and admins.
     */
    private void sendExpiryWarning() {
        String msg = MessageFormatter.warning("⚠ La suscripción de NexusSecurity expira en 7 días. " +
                "Renueva en https://nexussecurity.io/dashboard para evitar pérdida de protección.");
        logger.warning(msg);
        Bukkit.getOnlinePlayers().stream()
                .filter(p -> p.hasPermission("nexussecurity.admin"))
                .forEach(p -> p.sendMessage(msg));
    }

    /**
     * Schedules automatic module deactivation when grace period expires.
     */
    private void scheduleGraceExpiry() {
        threadPoolManager.schedule(
                "GracePeriodExpiry",
                () -> Bukkit.getScheduler().runTask(plugin, () -> {
                    if (!subscriptionActive || graceStartTime > 0) {
                        deactivateModules();
                        logger.severe("[Subscription] Grace period expired. All modules deactivated.");
                    }
                }),
                gracePeriodMs,
                TimeUnit.MILLISECONDS
        );
    }

    /**
     * Checks if we are still within the grace period.
     *
     * @return true if grace period is active
     */
    public boolean isGracePeriodActive() {
        if (graceStartTime < 0) return false;
        return System.currentTimeMillis() - graceStartTime < gracePeriodMs;
    }

    /**
     * Determines if a validation failure was due to a network error (vs. invalid key).
     *
     * @param response The failed response
     * @return true if the failure appears to be network-related
     */
    private boolean isNetworkError(SubscriptionResponse response) {
        String msg = response.getMessage().toLowerCase();
        return msg.contains("network") || msg.contains("timeout") ||
                msg.contains("connection") || msg.contains("unreachable");
    }

    /**
     * Saves subscription state to a local cache file for persistence across restarts.
     *
     * @param response The subscription to cache
     */
    private void saveSubscriptionCache(SubscriptionResponse response) {
        threadPoolManager.submit("SaveSubscriptionCache", () -> {
            File cacheFile = new File(plugin.getDataFolder(), CACHE_FILE);
            FileConfiguration cache = new YamlConfiguration();
            cache.set("valid", response.isValid());
            cache.set("plan", response.getPlan());
            cache.set("expiresAt", response.getExpiresAt());
            cache.set("message", response.getMessage());
            cache.set("cachedAt", System.currentTimeMillis());
            try {
                cache.save(cacheFile);
            } catch (IOException e) {
                logger.warning("[Subscription] Failed to save subscription cache: " + e.getMessage());
            }
        });
    }

    /**
     * Loads subscription state from the local cache file.
     *
     * @return Cached SubscriptionResponse, or null if not found/expired
     */
    private SubscriptionResponse loadCachedSubscription() {
        File cacheFile = new File(plugin.getDataFolder(), CACHE_FILE);
        if (!cacheFile.exists()) return null;

        FileConfiguration cache = YamlConfiguration.loadConfiguration(cacheFile);
        boolean valid = cache.getBoolean("valid", false);
        long expiresAt = cache.getLong("expiresAt", -1);

        if (valid && expiresAt > System.currentTimeMillis()) {
            return SubscriptionResponse.gracePeriod(expiresAt);
        }
        return null;
    }

    /**
     * Stops all scheduled tasks. Called on plugin disable.
     */
    public void shutdown() {
        if (revalidationTask != null) revalidationTask.cancel(false);
        if (expiryWarningTask != null) expiryWarningTask.cancel(false);
    }

    // ============================================================
    // GETTERS
    // ============================================================

    /** @return Whether the subscription is currently active */
    public boolean isSubscriptionActive() { return subscriptionActive; }

    /** @return The current subscription response (may be null before first validation) */
    public SubscriptionResponse getCurrentSubscription() { return currentSubscription; }
}
