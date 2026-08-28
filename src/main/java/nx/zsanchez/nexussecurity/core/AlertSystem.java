package nx.zsanchez.nexussecurity.core;

import nx.zsanchez.nexussecurity.NexusSecurity;
import nx.zsanchez.nexussecurity.util.MessageFormatter;
import nx.zsanchez.nexussecurity.util.TimeUtil;
import org.bukkit.Bukkit;
import org.bukkit.entity.Player;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Centralized alert system for NexusSecurity.
 * Dispatches alerts to the console, online admins, and the audit log
 * based on configured severity thresholds.
 *
 * <p>Severity Levels:</p>
 * <ul>
 *   <li><b>INFO</b>: Informational messages, minimal concern</li>
 *   <li><b>WARNING</b>: Suspicious activity detected, warrants attention</li>
 *   <li><b>CRITICAL</b>: Active threat detected, immediate action may be required</li>
 * </ul>
 */
public class AlertSystem {

    /** Severity levels ordered by importance. */
    public enum Severity {
        INFO, WARNING, CRITICAL;

        /**
         * Returns whether this severity is at least as important as the given level.
         *
         * @param minimum The minimum severity to compare against
         * @return true if this level >= minimum
         */
        public boolean isAtLeast(Severity minimum) {
            return this.ordinal() >= minimum.ordinal();
        }
    }

    private final NexusSecurity plugin;
    private final Logger logger;
    private final DatabaseManager databaseManager;
    private final BatchWriter batchWriter;

    /** Minimum severity for console alerts. */
    private Severity consoleSeverity;
    /** Minimum severity for in-game alerts. */
    private Severity inGameSeverity;
    /** Whether console alerts are enabled. */
    private boolean consoleEnabled;
    /** Whether in-game alerts are enabled. */
    private boolean inGameEnabled;

    /** Bounded ring buffer of the most recent alerts, for the web panel live feed. */
    private final ConcurrentLinkedDeque<AlertEntry> recentEvents = new ConcurrentLinkedDeque<>();
    private static final int MAX_RECENT_EVENTS = 200;

    /** Live subscribers (e.g. web panel SSE) notified on every new alert. */
    private final java.util.concurrent.CopyOnWriteArrayList<java.util.function.Consumer<AlertEntry>> subscribers = new java.util.concurrent.CopyOnWriteArrayList<>();

    /** Immutable record of a single alert, for external consumers (web panel). */
    public record AlertEntry(long timestamp, String severity, String module, String source, String description) {}

    /**
     * Creates the alert system and reads configuration.
     *
     * @param plugin          Main plugin instance
     * @param databaseManager Database for persisting events
     * @param batchWriter     Batch writer for efficient event persistence
     */
    public AlertSystem(NexusSecurity plugin, DatabaseManager databaseManager, BatchWriter batchWriter) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
        this.databaseManager = databaseManager;
        this.batchWriter = batchWriter;
        loadConfig();
    }

    /**
     * Loads alert configuration from config.yml.
     */
    public void loadConfig() {
        this.consoleEnabled = plugin.getConfig().getBoolean("notifications.console", true);
        this.inGameEnabled = plugin.getConfig().getBoolean("notifications.in-game", true);

        String consoleLevel = plugin.getConfig().getString("notifications.console-min-level", "info").toUpperCase();
        String inGameLevel = plugin.getConfig().getString("notifications.in-game-min-level", "warning").toUpperCase();

        try {
            this.consoleSeverity = Severity.valueOf(consoleLevel);
        } catch (IllegalArgumentException e) {
            this.consoleSeverity = Severity.INFO;
        }
        try {
            this.inGameSeverity = Severity.valueOf(inGameLevel);
        } catch (IllegalArgumentException e) {
            this.inGameSeverity = Severity.WARNING;
        }
    }

    /**
     * Dispatches an alert with the given severity.
     *
     * @param severity    The alert severity
     * @param module      The module generating the alert
     * @param source      The source identifier (IP, player name, file path, etc.)
     * @param description Human-readable description of the event
     */
    public void alert(Severity severity, String module, String source, String description) {
        // Persist to database via batch writer (async, non-blocking)
        batchWriter.queueEvent(severity.name(), module, source, description, null);

        // Keep a bounded recent-events buffer for the web panel live feed
        AlertEntry entry = new AlertEntry(System.currentTimeMillis(), severity.name(), module, source, description);
        recentEvents.addLast(entry);
        while (recentEvents.size() > MAX_RECENT_EVENTS) {
            recentEvents.pollFirst();
        }

        // Notify live subscribers (web panel SSE, external notifiers, etc.)
        for (var s : subscribers) {
            try { s.accept(entry); } catch (Exception ignored) {}
        }

        // Console output
        if (consoleEnabled && severity.isAtLeast(consoleSeverity)) {
            String prefix = "[" + module + "] ";
            switch (severity) {
                case INFO     -> logger.info(prefix + description);
                case WARNING  -> logger.warning(prefix + description);
                case CRITICAL -> logger.log(Level.SEVERE, prefix + "CRITICAL - " + description);
            }
        }

        // In-game notification to players with nexussecurity.alerts permission
        if (inGameEnabled && severity.isAtLeast(inGameSeverity)) {
            String formattedMessage = switch (severity) {
                case INFO     -> MessageFormatter.info("[" + module + "] " + description);
                case WARNING  -> MessageFormatter.warning("[" + module + "] " + description);
                case CRITICAL -> MessageFormatter.critical("[" + module + "] " + description);
            };

            // Must dispatch to main thread for Bukkit player interaction
            Bukkit.getScheduler().runTask(plugin, () -> {
                for (Player player : Bukkit.getOnlinePlayers()) {
                    if (player.hasPermission("nexussecurity.alerts")) {
                        player.sendMessage(formattedMessage);
                    }
                }
            });
        }
    }

    /**
     * Dispatches an INFO-level alert.
     *
     * @param module      Source module name
     * @param source      Source identifier
     * @param description Event description
     */
    public void info(String module, String source, String description) {
        alert(Severity.INFO, module, source, description);
    }

    /**
     * Dispatches a WARNING-level alert.
     *
     * @param module      Source module name
     * @param source      Source identifier
     * @param description Event description
     */
    public void warning(String module, String source, String description) {
        alert(Severity.WARNING, module, source, description);
    }

    /**
     * Dispatches a CRITICAL-level alert.
     *
     * @param module      Source module name
     * @param source      Source identifier
     * @param description Event description
     */
    public void critical(String module, String source, String description) {
        alert(Severity.CRITICAL, module, source, description);
    }

    /**
     * Returns a snapshot of the most recent alerts (oldest first).
     *
     * @return Recent alert entries, at most {@code MAX_RECENT_EVENTS}
     */
    public List<AlertEntry> getRecentEvents() {
        return new ArrayList<>(recentEvents);
    }

    /** Registers a live subscriber that receives every new alert (e.g. SSE feed). */
    public void subscribe(java.util.function.Consumer<AlertEntry> consumer) {
        if (consumer != null) subscribers.add(consumer);
    }

    /** Removes a previously registered live subscriber. */
    public void unsubscribe(java.util.function.Consumer<AlertEntry> consumer) {
        subscribers.remove(consumer);
    }
}
