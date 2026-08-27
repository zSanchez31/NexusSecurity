package nx.zsanchez.nexussecurity.modules.hackdetector;

import nx.zsanchez.nexussecurity.NexusSecurity;
import nx.zsanchez.nexussecurity.core.AlertSystem;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * Analyzes player command patterns to detect macros, bots, and command abuse.
 * Flags: command spamming, perfectly-timed macro execution, suspicious command sequences.
 */
public class CommandAnalyzer {

    private final NexusSecurity plugin;
    private final AlertSystem alertSystem;

    private int maxCommandsPerSecond;
    private boolean detectMacros;
    private List<String> suspiciousCommands;

    /** Map of player UUID → command timestamps (last 20 commands). */
    private final Map<UUID, List<Long>> commandHistory = new ConcurrentHashMap<>();
    /** Map of player UUID → last command timestamp (for interval analysis). */
    private final Map<UUID, Long> lastCommandTime = new ConcurrentHashMap<>();
    /** Map of player UUID → interval consistency score (for macro detection). */
    private final Map<UUID, List<Long>> intervalHistory = new ConcurrentHashMap<>();

    // Macro detection: If intervals between commands are suspiciously regular
    private static final double MACRO_INTERVAL_VARIANCE_THRESHOLD = 15.0; // ms standard deviation

    /**
     * Creates the command analyzer.
     *
     * @param plugin      Main plugin instance
     * @param alertSystem Alert system for command violations
     */
    public CommandAnalyzer(NexusSecurity plugin, AlertSystem alertSystem) {
        this.plugin = plugin;
        this.alertSystem = alertSystem;
        loadConfig();
    }

    /**
     * Loads command analyzer configuration.
     */
    public void loadConfig() {
        this.maxCommandsPerSecond = plugin.getConfig().getInt(
                "modules.hack-detector.commands.max-commands-per-second", 5);
        this.detectMacros = plugin.getConfig().getBoolean(
                "modules.hack-detector.commands.detect-macros", true);
        this.suspiciousCommands = plugin.getConfig().getStringList(
                "modules.hack-detector.commands.suspicious-commands");
    }

    /**
     * Analyzes a command execution for hack/bot indicators.
     *
     * @param playerUuid Player UUID
     * @param playerName Player name
     * @param command    Command string (without leading slash)
     * @param hasPermission Whether player has bypass permission
     * @return Violation type string, or null if clean
     */
    public String analyzeCommand(UUID playerUuid, String playerName, String command, boolean hasPermission) {
        if (hasPermission) return null;

        long now = System.currentTimeMillis();

        // 1. Suspicious command check
        String cmdLower = command.toLowerCase();
        for (String suspicious : suspiciousCommands) {
            if (cmdLower.startsWith(suspicious.toLowerCase())) {
                alertSystem.warning("HackDetector", playerName,
                        "Suspicious command executed: /" + command);
                return "SUSPICIOUS_COMMAND";
            }
        }

        // 2. Command rate check (commands per second)
        List<Long> history = commandHistory.computeIfAbsent(playerUuid, k -> new ArrayList<>());
        synchronized (history) {
            history.add(now);
            history.removeIf(t -> now - t > 1000);
            if (history.size() > maxCommandsPerSecond) {
                alertSystem.warning("HackDetector", playerName,
                        "Command spam: " + history.size() + " commands/second (max: " + maxCommandsPerSecond + ")");
                return "COMMAND_SPAM";
            }
        }

        // 3. Macro detection (suspiciously regular command intervals)
        if (detectMacros) {
            Long lastTime = lastCommandTime.get(playerUuid);
            if (lastTime != null) {
                long interval = now - lastTime;
                List<Long> intervals = intervalHistory.computeIfAbsent(playerUuid, k -> new ArrayList<>());
                synchronized (intervals) {
                    intervals.add(interval);
                    if (intervals.size() > 15) intervals.remove(0);

                    if (intervals.size() >= 10) {
                        double stdDev = computeStdDev(intervals);
                        if (stdDev < MACRO_INTERVAL_VARIANCE_THRESHOLD && interval < 500) {
                            alertSystem.warning("HackDetector", playerName,
                                    "Macro/Bot pattern: command intervals too regular (stdDev=" +
                                            String.format("%.1f", stdDev) + "ms)");
                            return "MACRO_DETECTED";
                        }
                    }
                }
            }
        }

        lastCommandTime.put(playerUuid, now);
        return null;
    }

    /**
     * Computes the standard deviation of a list of long values.
     *
     * @param values List of values
     * @return Standard deviation
     */
    private double computeStdDev(List<Long> values) {
        double mean = values.stream().mapToLong(Long::longValue).average().orElse(0);
        double variance = values.stream()
                .mapToDouble(v -> Math.pow(v - mean, 2))
                .average()
                .orElse(0);
        return Math.sqrt(variance);
    }

    /**
     * Clears player tracking data on logout.
     *
     * @param uuid Player UUID
     */
    public void cleanup(UUID uuid) {
        commandHistory.remove(uuid);
        lastCommandTime.remove(uuid);
        intervalHistory.remove(uuid);
    }
}
