package nx.zsanchez.nexussecurity.modules.integrity;

import nx.zsanchez.nexussecurity.NexusSecurity;
import nx.zsanchez.nexussecurity.core.*;

import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

/**
 * Module 6: Integrity — Core System File Integrity Monitor.
 * Provides real-time protection and monitoring of core configuration binaries and scripts.
 */
public class Integrity implements SecurityModule {

    private final NexusSecurity plugin;
    private final Logger logger;
    private final AlertSystem alertSystem;
    private final DatabaseManager databaseManager;
    private final ThreadPoolManager threadPoolManager;

    private FileWatcher fileWatcher;
    private boolean enabled = false;
    private ScheduledFuture<?> integrityCheckTask;
    private int checkIntervalMinutes;

    public Integrity(NexusSecurity plugin, AlertSystem alertSystem, DatabaseManager databaseManager,
                     ThreadPoolManager threadPoolManager) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
        this.alertSystem = alertSystem;
        this.databaseManager = databaseManager;
        this.threadPoolManager = threadPoolManager;
    }

    @Override
    public String getName() { return "Integrity"; }

    @Override
    public String getDescription() { return "Monitors system binaries and critical server configuration files for unauthorized alterations."; }

    @Override
    public void enable() {
        if (enabled) return;
        this.checkIntervalMinutes = plugin.getConfig().getInt("modules.integrity.check-interval-minutes", 15);
        this.fileWatcher = new FileWatcher(plugin, alertSystem, databaseManager);
        enabled = true;

        this.integrityCheckTask = threadPoolManager.scheduleAtFixedRate(
                "IntegrityCheck",
                () -> fileWatcher.checkCriticalFiles(),
                1,
                checkIntervalMinutes,
                TimeUnit.MINUTES
        );

        logger.info("[Integrity] Module enabled. Periodic check every " + checkIntervalMinutes + "m.");
    }

    @Override
    public void disable() {
        if (!enabled) return;
        if (integrityCheckTask != null && !integrityCheckTask.isCancelled()) {
            integrityCheckTask.cancel(false);
        }
        enabled = false;
        logger.info("[Integrity] Module disabled.");
    }

    @Override
    public boolean isEnabled() { return enabled; }

    public FileWatcher getFileWatcher() { return fileWatcher; }

    @Override
    public String getStatusSummary() {
        return "&aACTIVO &7| Check interval: &f" + checkIntervalMinutes + "m";
    }
}
