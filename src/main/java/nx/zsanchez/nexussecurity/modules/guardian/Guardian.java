package nx.zsanchez.nexussecurity.modules.guardian;

import nx.zsanchez.nexussecurity.NexusSecurity;
import nx.zsanchez.nexussecurity.core.*;

import java.util.Map;
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
        enabled = false;
        logger.info("[Guardian] Module disabled.");
    }

    @Override
    public boolean isEnabled() { return enabled; }

    private void loadConfig() {
        this.scanIntervalMinutes = plugin.getConfig().getInt("modules.guardian.scan-interval-minutes", 60);
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
