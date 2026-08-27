package nx.zsanchez.nexussecurity.modules.sentinel;

import nx.zsanchez.nexussecurity.NexusSecurity;
import nx.zsanchez.nexussecurity.core.*;

import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

/**
 * Module 3: Sentinel — Continuous 24/7 Monitoring.
 * Tracks host hardware state, active ports, connection events, and security status.
 */
public class Sentinel implements SecurityModule {

    private final NexusSecurity plugin;
    private final Logger logger;
    private final AlertSystem alertSystem;
    private final PerformanceMonitor performanceMonitor;
    private final ThreadPoolManager threadPoolManager;

    private SystemMonitor systemMonitor;
    private ConnectionMonitor connectionMonitor;

    private boolean enabled = false;
    private ScheduledFuture<?> metricsTask;
    private int metricsIntervalSeconds;

    public Sentinel(NexusSecurity plugin, AlertSystem alertSystem, PerformanceMonitor performanceMonitor,
                    ThreadPoolManager threadPoolManager) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
        this.alertSystem = alertSystem;
        this.performanceMonitor = performanceMonitor;
        this.threadPoolManager = threadPoolManager;
    }

    @Override
    public String getName() { return "Sentinel"; }

    @Override
    public String getDescription() { return "Continuous 24/7 system health, resource, and connection monitoring."; }

    @Override
    public void enable() {
        if (enabled) return;
        loadConfig();

        this.systemMonitor = new SystemMonitor(plugin, alertSystem, performanceMonitor);
        this.connectionMonitor = new ConnectionMonitor(plugin, alertSystem);

        enabled = true;

        this.metricsTask = threadPoolManager.scheduleAtFixedRate(
                "SentinelMetrics",
                this::runMetricsCycle,
                10,
                metricsIntervalSeconds,
                TimeUnit.SECONDS
        );

        logger.info("[Sentinel] Module enabled. Interval: " + metricsIntervalSeconds + "s.");
    }

    @Override
    public void disable() {
        if (!enabled) return;
        if (metricsTask != null && !metricsTask.isCancelled()) {
            metricsTask.cancel(false);
        }
        enabled = false;
        logger.info("[Sentinel] Module disabled.");
    }

    @Override
    public boolean isEnabled() { return enabled; }

    private void loadConfig() {
        this.metricsIntervalSeconds = plugin.getConfig().getInt("modules.sentinel.metrics-interval-seconds", 30);
    }

    private void runMetricsCycle() {
        if (!enabled) return;
        systemMonitor.sample();
        connectionMonitor.checkPorts();
    }

    public SystemMonitor getSystemMonitor() { return systemMonitor; }
    public ConnectionMonitor getConnectionMonitor() { return connectionMonitor; }

    @Override
    public double getResourceUsageScore() {
        double cpuFrac = Math.max(0.0, Math.min(1.0, performanceMonitor.getCpuUsagePercent() / 100.0));
        double totalRam = performanceMonitor.getTotalRamMb();
        double ramFrac = totalRam > 0
                ? Math.max(0.0, Math.min(1.0, performanceMonitor.getUsedRamMb() / totalRam))
                : 0.0;
        double tpsFrac = Math.max(0.0, Math.min(1.0, 1.0 - (performanceMonitor.getCurrentTps() / 20.0)));
        return Math.max(0.0, Math.min(1.0, 0.3 * cpuFrac + 0.4 * ramFrac + 0.3 * tpsFrac));
    }

    @Override
    public String getStatusSummary() {
        return "&aACTIVO &7| Interval: &f" + metricsIntervalSeconds + "s | " + performanceMonitor.getStatusSummary();
    }
}
