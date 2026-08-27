package nx.zsanchez.nexussecurity.core;

import java.util.UUID;

/**
 * Base interface that all NexusSecurity security modules must implement.
 * The {@link ModuleManager} uses this interface to manage the lifecycle of all modules
 * in a uniform way, enabling/disabling them based on subscription status and performance thresholds.
 *
 * <p>Implementors should:</p>
 * <ul>
 *   <li>Perform all heavy initialization asynchronously inside {@link #enable()}</li>
 *   <li>Release all resources (threads, DB connections, caches) inside {@link #disable()}</li>
 *   <li>Be safe to call {@link #enable()} and {@link #disable()} multiple times</li>
 * </ul>
 */
public interface SecurityModule {

    /**
     * Returns the unique name of this module.
     * Used in logs, commands and configuration references.
     *
     * @return Module name (e.g., "Shield", "HackDetector")
     */
    String getName();

    /**
     * Returns a brief description of the module's purpose.
     *
     * @return Human-readable description
     */
    String getDescription();

    /**
     * Activates the module and starts all its monitoring and protection tasks.
     * This method is called when the plugin starts or the subscription is validated.
     * Implementations should be idempotent — calling enable() on an already-enabled
     * module should be safe and have no effect.
     */
    void enable();

    /**
     * Deactivates the module and releases all associated resources.
     * Called when the plugin is disabled, the subscription expires, or performance
     * thresholds are exceeded. Implementations must cancel all scheduled tasks and
     * release memory/connections.
     */
    void disable();

    /**
     * Returns whether this module is currently active.
     *
     * @return true if the module is running, false otherwise
     */
    boolean isEnabled();

    /**
     * Returns the current resource usage score of this module (0.0 - 1.0).
     * Used by {@link PerformanceMonitor} to decide whether to auto-disable the module.
     * 0.0 means no resource usage; 1.0 means at maximum threshold.
     *
     * @return Resource usage score between 0.0 and 1.0
     */
    default double getResourceUsageScore() {
        return 0.0;
    }

    /**
     * Returns the configuration key of this module (lowercase, kebab-case).
     * Used for the {@code modules.<key>.enabled} toggle and module settings.
     *
     * @return Module config key (e.g., "hack-detector", "defender-ai")
     */
    default String getConfigKey() {
        return getName().replace(" ", "")
                .replaceAll("([a-z0-9])([A-Z])", "$1-$2")
                .toLowerCase();
    }

    /**
     * Returns a brief status summary for the /security status command.
     *
     * @return Status summary string (may include ChatColor codes)
     */
    default String getStatusSummary() {
        return isEnabled() ? "&aACTIVO" : "&cINACTIVO";
    }

    /**
     * Called when a player disconnects, giving the module a chance to release any
     * per-player tracked state (locations, violation counters, command history, etc.)
     * so memory does not leak for long-running servers.
     *
     * <p>The default implementation does nothing. Modules that keep per-player maps should
     * override this to evict the entry for the given UUID.</p>
     *
     * @param playerUuid UUID of the player who quit
     */
    default void onPlayerQuit(UUID playerUuid) {
        // No-op by default
    }
}
