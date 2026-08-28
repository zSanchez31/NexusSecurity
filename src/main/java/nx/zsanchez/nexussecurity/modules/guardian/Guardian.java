package nx.zsanchez.nexussecurity.modules.guardian;

import nx.zsanchez.nexussecurity.NexusSecurity;
import nx.zsanchez.nexussecurity.core.*;

import org.bukkit.event.Listener;
import org.bukkit.event.EventHandler;
import org.bukkit.event.player.PlayerJoinEvent;

import java.net.InetAddress;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

/**
 * Module 2: Guardian — Antimalware and Integrity Protection.
 * Performs scheduled background scans of server files, monitors JAR modifications,
 * and maintains baseline file integrity.
 */
public class Guardian implements SecurityModule {

    private final NexusSecurity plugin;
    private final Logger logger;
    private final AlertSystem alertSystem;
    private final CacheManager cacheManager;
    private final DatabaseManager databaseManager;
    private final ThreadPoolManager threadPoolManager;

    private FileScanner fileScanner;
    private IntegrityHasher integrityHasher;

    private boolean enabled = false;
    private ScheduledFuture<?> scanTask;
    private int scanIntervalMinutes;

    private boolean antiBotEnabled;
    private int botWindowSeconds;
    private int botMaxJoinsPerIp;
    private boolean botKick;
    private final Map<InetAddress, Deque<Long>> joinTimes = new ConcurrentHashMap<>();
    private BotListener botListener;

    public Guardian(NexusSecurity plugin, CacheManager cacheManager, DatabaseManager databaseManager,
                    AlertSystem alertSystem, ThreadPoolManager threadPoolManager) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
        this.cacheManager = cacheManager;
        this.databaseManager = databaseManager;
        this.alertSystem = alertSystem;
        this.threadPoolManager = threadPoolManager;
    }

    @Override
    public String getName() { return "Guardian"; }

    @Override
    public String getDescription() { return "Antimalware and integrity verification module."; }

    @Override
    public void enable() {
        if (enabled) return;
        loadConfig();

        this.fileScanner = new FileScanner(plugin, alertSystem, cacheManager);
        this.integrityHasher = new IntegrityHasher(plugin, databaseManager);

        enabled = true;

        if (antiBotEnabled) {
            this.botListener = new BotListener();
            try { org.bukkit.Bukkit.getPluginManager().registerEvents(botListener, plugin); } catch (Exception ignored) {}
        }

        // Generate initial baseline asynchronously
        threadPoolManager.submit("GuardianBaseline", () -> integrityHasher.generateBaseline());

        // Schedule periodic file scanning
        this.scanTask = threadPoolManager.scheduleAtFixedRate(
                "GuardianScan",
                this::runScan,
                5,
                scanIntervalMinutes,
                TimeUnit.MINUTES
        );

        logger.info("[Guardian] Module enabled. Periodic scan every " + scanIntervalMinutes + "m.");
    }

    @Override
    public void disable() {
        if (!enabled) return;
        if (scanTask != null && !scanTask.isCancelled()) {
            scanTask.cancel(false);
        }
        if (botListener != null) botListener.active = false;
        enabled = false;
        logger.info("[Guardian] Module disabled.");
    }

    @Override
    public boolean isEnabled() { return enabled; }

    private void loadConfig() {
        this.scanIntervalMinutes = plugin.getConfig().getInt("modules.guardian.scan-interval-minutes", 60);
        this.antiBotEnabled = plugin.getConfig().getBoolean("modules.guardian.anti-bot.enabled", true);
        this.botWindowSeconds = Math.max(1, plugin.getConfig().getInt("modules.guardian.anti-bot.window-seconds", 10));
        this.botMaxJoinsPerIp = Math.max(2, plugin.getConfig().getInt("modules.guardian.anti-bot.max-joins-per-ip", 5));
        this.botKick = plugin.getConfig().getBoolean("modules.guardian.anti-bot.kick", true);
    }

    /**
     * Detects bot/join-flood patterns: too many joins from the same IP in a short window.
     */
    private class BotListener implements Listener {
        private volatile boolean active = true;
        @EventHandler
        public void onJoin(PlayerJoinEvent event) {
            if (!active) return;
            InetAddress ip = event.getPlayer().getAddress() != null
                    ? event.getPlayer().getAddress().getAddress() : null;
            if (ip == null) return;
            long now = System.currentTimeMillis();
            Deque<Long> times = joinTimes.computeIfAbsent(ip, k -> new ArrayDeque<>());
            synchronized (times) {
                times.addLast(now);
                while (!times.isEmpty() && now - times.peekFirst() > botWindowSeconds * 1000L) {
                    times.pollFirst();
                }
                if (times.size() > botMaxJoinsPerIp) {
                    alertSystem.warning("Guardian", ip.getHostAddress(),
                            "Posible bot/join-flood: " + times.size() + " joins desde " + ip.getHostAddress()
                                    + " en " + botWindowSeconds + "s");
                    if (botKick && event.getPlayer().isOnline()) {
                        event.getPlayer().kickPlayer("§cConexión bloqueada por posible bot (join-flood).");
                    }
                    times.clear();
                }
            }
        }
    }

    /**
     * Executes manual file scan and integrity check.
     */
    public void runScan() {
        if (!enabled) return;
        logger.info("[Guardian] Running scheduled file integrity & antimalware scan...");
        fileScanner.performFullScan();

        Map<String, String> modified = integrityHasher.verifyIntegrity();
        if (!modified.isEmpty()) {
            for (Map.Entry<String, String> entry : modified.entrySet()) {
                alertSystem.critical("Guardian", entry.getKey(),
                        "UNAUTHORIZED FILE MODIFICATION: SHA-256 mismatch for plugin " + entry.getKey());
            }
        }
    }

    public FileScanner getFileScanner() { return fileScanner; }
    public IntegrityHasher getIntegrityHasher() { return integrityHasher; }

    @Override
    public double getResourceUsageScore() {
        long cacheSize = cacheManager.getFileHashCacheSize();
        return Math.min(1.0, cacheSize / 5000.0);
    }

    @Override
    public String getStatusSummary() {
        return "&aACTIVO &7| Scan interval: &f" + scanIntervalMinutes + "m";
    }
}
