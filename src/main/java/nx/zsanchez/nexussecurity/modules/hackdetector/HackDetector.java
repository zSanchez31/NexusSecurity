package nx.zsanchez.nexussecurity.modules.hackdetector;

import nx.zsanchez.nexussecurity.NexusSecurity;
import nx.zsanchez.nexussecurity.core.*;
import org.bukkit.BanList;
import org.bukkit.Bukkit;
import org.bukkit.entity.Entity;
import org.bukkit.entity.Player;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

/**
 * Module 11: HackDetector — Comprehensive hack and exploitation detection.
 * Orchestrates MovementAnalyzer, CombatAnalyzer, and CommandAnalyzer to provide
 * multi-vector hack detection with configurable sensitivity and automatic actions.
 *
 * <p>Violation system: Each detected violation increments a counter per player.
 * When the counter reaches the configured threshold, the configured action is taken.</p>
 */
public class HackDetector implements nx.zsanchez.nexussecurity.core.SecurityModule {

    private final NexusSecurity plugin;
    private final Logger logger;
    private final AlertSystem alertSystem;
    private final DatabaseManager databaseManager;
    private final EventBus eventBus;

    private MovementAnalyzer movementAnalyzer;
    private CombatAnalyzer combatAnalyzer;
    private CommandAnalyzer commandAnalyzer;

    private boolean enabled = false;
    private int violationsBeforeAction;
    private String defaultAction;
    private long banDurationMinutes;
    private boolean notifyAdmins;
    private boolean movementEnabled;
    private boolean combatEnabled;
    private boolean commandsEnabled;

    /** Accumulated violation counts per player (reset after action). */
    private final Map<UUID, Integer> violationCounts = new ConcurrentHashMap<>();
    /** Total violations detected since module start. */
    private volatile long totalViolations = 0;

    /**
     * Creates the HackDetector module.
     *
     * @param plugin          Main plugin instance
     * @param alertSystem     Alert system
     * @param databaseManager Database manager
     * @param eventBus        Internal event bus
     */
    public HackDetector(NexusSecurity plugin, AlertSystem alertSystem,
                        DatabaseManager databaseManager, EventBus eventBus) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
        this.alertSystem = alertSystem;
        this.databaseManager = databaseManager;
        this.eventBus = eventBus;
    }

    @Override
    public String getName() { return "HackDetector"; }

    @Override
    public String getDescription() { return "Detects hacks: speed, flight, reach, killaura, macros and more."; }

    @Override
    public void enable() {
        if (enabled) return;
        loadConfig();

        this.movementAnalyzer = new MovementAnalyzer(plugin, alertSystem);
        this.combatAnalyzer = new CombatAnalyzer(plugin, alertSystem);
        this.commandAnalyzer = new CommandAnalyzer(plugin, alertSystem);

        enabled = true;
        logger.info("[HackDetector] Enabled. Movement=" + movementEnabled +
                ", Combat=" + combatEnabled + ", Commands=" + commandsEnabled +
                ", Sensitivity violations=" + violationsBeforeAction);
    }

    @Override
    public void disable() {
        if (!enabled) return;
        violationCounts.clear();
        enabled = false;
        logger.info("[HackDetector] Disabled.");
    }

    @Override
    public boolean isEnabled() { return enabled; }

    /**
     * Loads HackDetector configuration.
     */
    private void loadConfig() {
        violationsBeforeAction = plugin.getConfig().getInt(
                "modules.hack-detector.violations-before-action", 5);
        defaultAction = plugin.getConfig().getString(
                "modules.hack-detector.default-action", "temp-ban");
        banDurationMinutes = plugin.getConfig().getLong(
                "modules.hack-detector.ban-duration-minutes", 1440);
        notifyAdmins = plugin.getConfig().getBoolean(
                "modules.hack-detector.notify-admins", true);
        movementEnabled = plugin.getConfig().getBoolean(
                "modules.hack-detector.movement.enabled", true);
        combatEnabled = plugin.getConfig().getBoolean(
                "modules.hack-detector.combat.enabled", true);
        commandsEnabled = plugin.getConfig().getBoolean(
                "modules.hack-detector.commands.enabled", true);
    }

    /**
     * Analyzes a player movement event. Must be called from the main thread.
     *
     * @param player Player who moved
     * @param from   Previous location
     * @param to     New location
     */
    public void onPlayerMove(Player player, org.bukkit.Location from, org.bukkit.Location to) {
        if (!enabled || !movementEnabled) return;
        String violation = movementAnalyzer.analyze(player, from, to);
        if (violation != null) {
            recordViolation(player, violation, "Movement: " + violation);
        }
    }

    /**
     * Analyzes a player attack event.
     *
     * @param player Player attacking
     * @param target Attacked entity
     */
    public void onPlayerAttack(Player player, Entity target) {
        if (!enabled || !combatEnabled) return;
        combatAnalyzer.recordRotation(player);
        String violation = combatAnalyzer.analyzeAttack(player, target);
        if (violation != null) {
            recordViolation(player, violation, "Combat: " + violation);
        }
    }

    /**
     * Analyzes a player command execution.
     *
     * @param player  Player executing the command
     * @param command Command string (without slash)
     */
    public void onCommand(Player player, String command) {
        if (!enabled || !commandsEnabled) return;
        String violation = commandAnalyzer.analyzeCommand(
                player.getUniqueId(), player.getName(), command,
                player.hasPermission("nexussecurity.bypass"));
        if (violation != null) {
            recordViolation(player, violation, "Command: " + violation);
        }
    }

    /**
     * Records a violation for a player and takes action if threshold is reached.
     *
     * @param player    The violating player
     * @param type      Violation type
     * @param details   Violation details for logging
     */
    private void recordViolation(Player player, String type, String details) {
        totalViolations++;
        UUID uuid = player.getUniqueId();
        int count = violationCounts.merge(uuid, 1, Integer::sum);

        // Persist to database off the main thread (recordViolation performs blocking I/O)
        final String playerName = player.getName();
        final String detailsCopy = details;
        plugin.getThreadPoolManager().submit("HackDetector-ViolationDB", () ->
                databaseManager.recordViolation(
                        uuid.toString(), playerName, type, detailsCopy));

        // Publish event
        eventBus.publish(EventBus.EVENT_HACK_DETECTED, Map.of(
                "player", player.getName(),
                "type", type,
                "count", count
        ));

        if (notifyAdmins) {
            // Already logged by alertSystem; additional notification to staff
            String staffMsg = nx.zsanchez.nexussecurity.util.MessageFormatter.warning(
                    "⚔ " + player.getName() + " - Violación #" + count + " [" + type + "] " + details);
            Bukkit.getOnlinePlayers().stream()
                    .filter(p -> p.hasPermission("nexussecurity.alerts") && !p.equals(player))
                    .forEach(p -> p.sendMessage(staffMsg));
        }

        // Take action if threshold reached
        if (count >= violationsBeforeAction) {
            violationCounts.put(uuid, 0); // Reset counter after action
            takeAction(player, type, count);
        }
    }

    /**
     * Executes the configured action against a confirmed hacker.
     *
     * @param player    The player to act against
     * @param violation The triggering violation type
     * @param count     Total violation count
     */
    private void takeAction(Player player, String violation, int count) {
        String reason = "NexusSecurity HackDetector: " + violation + " (" + count + " violations)";

        switch (defaultAction.toLowerCase()) {
            case "kick" -> {
                Bukkit.getScheduler().runTask(plugin, () ->
                        player.kickPlayer(nx.zsanchez.nexussecurity.util.MessageFormatter.colorize(
                                "&c&lNexusSecurity\n&cHack detectado: " + violation)));
            }
            case "ban" -> {
                Bukkit.getBanList(BanList.Type.NAME).addBan(
                        player.getName(), reason, null, "NexusSecurity");
                Bukkit.getScheduler().runTask(plugin, () -> player.kickPlayer(
                        nx.zsanchez.nexussecurity.util.MessageFormatter.colorize(
                                "&c&lBanneado permanentemente\n&c" + reason)));
            }
            case "temp-ban" -> {
                Date expiry = new Date(System.currentTimeMillis() + banDurationMinutes * 60 * 1000L);
                Bukkit.getBanList(BanList.Type.NAME).addBan(
                        player.getName(), reason, expiry, "NexusSecurity");
                Bukkit.getScheduler().runTask(plugin, () -> player.kickPlayer(
                        nx.zsanchez.nexussecurity.util.MessageFormatter.colorize(
                                "&c&lBanneado temporalmente\n&c" + reason)));
            }
            default -> {
                // "warn" — just alert, no kick
                alertSystem.critical("HackDetector", player.getName(),
                        "Confirmed hacker (action: warn). Violations: " + count + ", Type: " + violation);
            }
        }

        alertSystem.critical("HackDetector", player.getName(),
                "Action taken [" + defaultAction.toUpperCase() + "]: " +
                        count + " violations, latest: " + violation);
    }

    /**
     * Cleans up player data on logout.
     *
     * @param player Player who disconnected
     */
    public void onPlayerQuit(Player player) {
        onPlayerQuit(player.getUniqueId());
    }

    @Override
    public void onPlayerQuit(UUID uuid) {
        violationCounts.remove(uuid);
        if (movementAnalyzer != null) movementAnalyzer.cleanup(uuid);
        if (combatAnalyzer != null) combatAnalyzer.cleanup(uuid);
        if (commandAnalyzer != null) commandAnalyzer.cleanup(uuid);
    }

    /**
     * Returns the current violation count for a player.
     *
     * @param uuid Player UUID
     * @return Current active violation count
     */
    public int getViolationCount(UUID uuid) {
        return violationCounts.getOrDefault(uuid, 0);
    }

    /** @return Copy of active violation counts per UUID (suspects) */
    public java.util.Map<UUID, Integer> getActiveViolationCounts() {
        return new java.util.HashMap<>(violationCounts);
    }

    @Override
    public String getStatusSummary() {
        return "&aACTIVO &7| Total violations: &c" + totalViolations +
                " &7| Active suspects: &e" + violationCounts.size();
    }
}
