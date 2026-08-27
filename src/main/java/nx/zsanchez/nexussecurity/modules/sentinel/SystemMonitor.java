package nx.zsanchez.nexussecurity.modules.sentinel;

import nx.zsanchez.nexussecurity.NexusSecurity;
import nx.zsanchez.nexussecurity.core.AlertSystem;
import nx.zsanchez.nexussecurity.core.PerformanceMonitor;

import java.io.File;
import java.util.logging.Logger;

/**
 * Subsystem of Sentinel that checks host CPU, RAM, and Disk space against configured alert thresholds.
 */
public class SystemMonitor {

    private final NexusSecurity plugin;
    private final Logger logger;
    private final AlertSystem alertSystem;
    private final PerformanceMonitor performanceMonitor;

    private int cpuAlertThreshold;
    private int ramAlertThreshold;
    private int diskAlertThreshold;

    public SystemMonitor(NexusSecurity plugin, AlertSystem alertSystem, PerformanceMonitor performanceMonitor) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
        this.alertSystem = alertSystem;
        this.performanceMonitor = performanceMonitor;
        loadConfig();
    }

    public void loadConfig() {
        this.cpuAlertThreshold = plugin.getConfig().getInt("modules.sentinel.cpu-alert-threshold", 85);
        this.ramAlertThreshold = plugin.getConfig().getInt("modules.sentinel.ram-alert-threshold", 90);
        this.diskAlertThreshold = plugin.getConfig().getInt("modules.sentinel.disk-alert-threshold", 95);
    }

    /**
     * Samples system health and fires alerts if thresholds are exceeded.
     */
    public void sample() {
        double cpu = performanceMonitor.getCpuUsagePercent();
        long usedRam = performanceMonitor.getUsedRamMb();
        long totalRam = performanceMonitor.getTotalRamMb();

        if (totalRam > 0) {
            double ramPercent = ((double) usedRam / totalRam) * 100.0;
            if (ramPercent >= ramAlertThreshold) {
                alertSystem.warning("Sentinel", "RAM",
                        String.format("High RAM usage detected: %.1f%% (%dMB / %dMB)", ramPercent, usedRam, totalRam));
            }
        }

        if (cpu >= cpuAlertThreshold) {
            alertSystem.warning("Sentinel", "CPU",
                    String.format("High CPU usage detected: %.1f%%", cpu));
        }

        // Check Disk space
        File root = plugin.getDataFolder().getParentFile();
        if (root != null) {
            long totalSpace = root.getTotalSpace();
            long freeSpace = root.getFreeSpace();
            if (totalSpace > 0) {
                double usedDiskPercent = ((double) (totalSpace - freeSpace) / totalSpace) * 100.0;
                if (usedDiskPercent >= diskAlertThreshold) {
                    alertSystem.critical("Sentinel", "Disk",
                            String.format("Disk space nearly exhausted: %.1f%% used (%dMB free)",
                                    usedDiskPercent, freeSpace / (1024 * 1024)));
                }
            }
        }
    }
}
