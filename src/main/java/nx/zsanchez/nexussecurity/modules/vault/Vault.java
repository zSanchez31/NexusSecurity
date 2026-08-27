package nx.zsanchez.nexussecurity.modules.vault;

import nx.zsanchez.nexussecurity.NexusSecurity;
import nx.zsanchez.nexussecurity.core.*;

import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

/**
 * Module 5: Vault — Automated Backups and Disaster Recovery.
 * Manages scheduled, incremental, encrypted backups of server worlds, configurations, and plugins.
 */
public class Vault implements SecurityModule {

    private final NexusSecurity plugin;
    private final Logger logger;
    private final AlertSystem alertSystem;
    private final ThreadPoolManager threadPoolManager;

    private BackupScheduler backupScheduler;
    private boolean enabled = false;
    private ScheduledFuture<?> scheduledBackupTask;

    public Vault(NexusSecurity plugin, AlertSystem alertSystem, ThreadPoolManager threadPoolManager) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
        this.alertSystem = alertSystem;
        this.threadPoolManager = threadPoolManager;
    }

    @Override
    public String getName() { return "Vault"; }

    @Override
    public String getDescription() { return "Automated, encrypted server backups and disaster recovery module."; }

    @Override
    public void enable() {
        if (enabled) return;
        this.backupScheduler = new BackupScheduler(plugin, alertSystem, threadPoolManager);
        enabled = true;

        // Schedule periodic backups according to the configured schedule (default: daily at backup-hour)
        String schedule = plugin.getConfig().getString("modules.vault.schedule", "daily").toLowerCase();
        long periodMinutes;
        switch (schedule) {
            case "hourly" -> periodMinutes = 60;
            case "weekly" -> periodMinutes = 7 * 24 * 60;
            case "cron" -> {
                logger.warning("[Vault] Cron schedule not supported; falling back to daily. Use daily/weekly/hourly.");
                periodMinutes = 24 * 60;
            }
            default -> periodMinutes = 24 * 60; // daily
        }

        long initialDelayMinutes = computeInitialDelay(periodMinutes);
        this.scheduledBackupTask = threadPoolManager.scheduleAtFixedRate(
                "VaultScheduledBackup",
                () -> backupScheduler.performBackupNow(),
                initialDelayMinutes,
                periodMinutes,
                TimeUnit.MINUTES
        );

        logger.info("[Vault] Module enabled. Scheduled backups every " + periodMinutes + "m (first in " + initialDelayMinutes + "m).");
    }

    /**
     * Computes the delay until the next backup, honoring the configured backup-hour
     * for daily/weekly schedules.
     *
     * @param periodMinutes Backup period in minutes
     * @return Initial delay in minutes (minimum 1)
     */
    private long computeInitialDelay(long periodMinutes) {
        int backupHour = plugin.getConfig().getInt("modules.vault.backup-hour", 3);
        java.time.LocalDateTime now = java.time.LocalDateTime.now();
        java.time.LocalDateTime next = now.toLocalDate().atTime(Math.max(0, Math.min(23, backupHour)), 0);
        if (!next.isAfter(now)) next = next.plusDays(1);
        long delayMinutes = java.time.Duration.between(now, next).toMinutes();
        if (periodMinutes <= 24 * 60) {
            // Hourly: align to top of the hour
            if (periodMinutes == 60) {
                delayMinutes = (60 - now.getMinute()) % 60;
                if (delayMinutes == 0) delayMinutes = 60;
            }
        } else {
            // Weekly: keep alignment to backup-hour
            delayMinutes = Math.min(delayMinutes, periodMinutes);
        }
        return Math.max(1, delayMinutes);
    }

    @Override
    public void disable() {
        if (!enabled) return;
        if (scheduledBackupTask != null && !scheduledBackupTask.isCancelled()) {
            scheduledBackupTask.cancel(false);
        }
        enabled = false;
        logger.info("[Vault] Module disabled.");
    }

    @Override
    public boolean isEnabled() { return enabled; }

    public BackupScheduler getBackupScheduler() { return backupScheduler; }

    @Override
    public double getResourceUsageScore() {
        return backupScheduler != null && backupScheduler.isBackupInProgress() ? 1.0 : 0.0;
    }

    @Override
    public String getStatusSummary() {
        return "&aACTIVO &7| Encrypted: &f" + plugin.getConfig().getBoolean("modules.vault.encrypt", true);
    }
}
