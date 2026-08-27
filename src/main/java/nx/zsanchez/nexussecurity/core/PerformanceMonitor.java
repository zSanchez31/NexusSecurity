package nx.zsanchez.nexussecurity.core;

import nx.zsanchez.nexussecurity.NexusSecurity;
import org.bukkit.Bukkit;

import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.OperatingSystemMXBean;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;
import java.util.stream.Collectors;

/**
 * Monitors server performance (TPS, CPU, RAM) at configurable intervals.
 * When resource usage exceeds configured thresholds, it publishes metrics updates
 * via {@link EventBus} and can trigger module auto-disable to protect server stability.
 *
 * <p>Key features:</p>
 * <ul>
 *   <li>TPS measurement using Paper's built-in API</li>
 *   <li>JVM heap and process CPU monitoring via MXBeans</li>
 *   <li>Auto-disable of non-critical modules when thresholds are exceeded</li>
 *   <li>Integrated profiling: tracks min/max/average TPS over the monitoring window</li>
 * </ul>
 */
public class PerformanceMonitor {

    private final NexusSecurity plugin;
    private final Logger logger;
    private final EventBus eventBus;
    private final ModuleManager moduleManager;

    // Thresholds (read from config)
    private double tpsThreshold;
    private double maxCpuPercent;
    private long maxRamMb;

    // Auto-disable config
    private boolean autoDisableEnabled;
    private double moduleScoreThreshold;
    private boolean reEnableOnRecovery;
    private long autoDisableCooldownMs;
    private Set<String> excludedModules = Set.of();
    private long lastAutoDisableAction;
    private final Set<String> autoDisabledModules = ConcurrentHashMap.newKeySet();

    // Performance metrics (updated each cycle)
    private volatile double currentTps = 20.0;
    private volatile double cpuUsagePercent = 0.0;
    private volatile long usedRamMb = 0;
    private volatile long totalRamMb = 0;

    // Running stats
    private double minTps = 20.0;
    private double maxTps = 20.0;
    private double avgTps = 20.0;
    private long sampleCount = 0;
    private long totalTps = 0;

    // History ring buffers for panel charts (capped)
    private static final int HISTORY_CAP = 60;
    private final java.util.ArrayDeque<Double> tpsHistory = new java.util.ArrayDeque<>();
    private final java.util.ArrayDeque<Long> ramHistory = new java.util.ArrayDeque<>();
    private final java.util.ArrayDeque<Double> cpuHistory = new java.util.ArrayDeque<>();

    // Throttle for threshold warning logs (avoid spamming every monitoring cycle)
    private static final long THRESHOLD_WARN_INTERVAL_MS = 5 * 60_000L;
    private final java.util.Map<String, Long> lastThresholdWarn = new java.util.concurrent.ConcurrentHashMap<>();

    private final OperatingSystemMXBean osMxBean;
    private final MemoryMXBean memoryMxBean;
    private ScheduledFuture<?> monitorTask;
    private final int metricsIntervalSeconds;

    /**
     * Creates the performance monitor.
     *
     * @param plugin        Main plugin instance
     * @param eventBus      Event bus for publishing metric updates
     * @param moduleManager Module manager for auto-disable decisions
     */
    public PerformanceMonitor(NexusSecurity plugin, EventBus eventBus, ModuleManager moduleManager) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
        this.eventBus = eventBus;
        this.moduleManager = moduleManager;
        this.osMxBean = ManagementFactory.getOperatingSystemMXBean();
        this.memoryMxBean = ManagementFactory.getMemoryMXBean();
        this.metricsIntervalSeconds = plugin.getConfig().getInt("modules.sentinel.metrics-interval-seconds", 30);
        loadThresholds();
    }

    /**
     * Loads performance thresholds from config.
     */
    public void loadThresholds() {
        this.tpsThreshold = plugin.getConfig().getDouble("performance.tps-threshold", 17.0);
        this.maxCpuPercent = plugin.getConfig().getDouble("performance.max-cpu-percent", 15.0);
        this.maxRamMb = plugin.getConfig().getLong("performance.max-ram-mb", 512);

        this.autoDisableEnabled = plugin.getConfig().getBoolean("performance.auto-disable.enabled", true);
        this.moduleScoreThreshold = plugin.getConfig().getDouble("performance.auto-disable.module-score-threshold", 0.5);
        this.reEnableOnRecovery = plugin.getConfig().getBoolean("performance.auto-disable.re-enable-on-recovery", true);
        this.autoDisableCooldownMs = plugin.getConfig().getLong("performance.auto-disable.cooldown-minutes", 10) * 60000L;
        this.excludedModules = plugin.getConfig().getStringList("performance.auto-disable.excluded-modules")
                .stream().map(PerformanceMonitor::normalizeName).collect(Collectors.toSet());
    }

    /**
     * Starts the performance monitoring task.
     */
    public void start(ThreadPoolManager threadPoolManager) {
        monitorTask = threadPoolManager.scheduleAtFixedRate(
                "PerformanceMonitor",
                this::collectMetrics,
                metricsIntervalSeconds,
                metricsIntervalSeconds,
                TimeUnit.SECONDS
        );
        logger.info("[PerformanceMonitor] Started (interval: " + metricsIntervalSeconds + "s).");
    }

    /**
     * Collects current performance metrics.
     * Runs asynchronously; TPS is fetched via Bukkit scheduler to access Paper API safely.
     */
    private void collectMetrics() {
        // Collect JVM metrics (thread-safe, no Bukkit API)
        var heapUsage = memoryMxBean.getHeapMemoryUsage();
        this.usedRamMb = heapUsage.getUsed() / (1024 * 1024);
        this.totalRamMb = heapUsage.getMax() / (1024 * 1024);

        // Get CPU load (may return -1.0 if not available)
        double rawCpu = -1.0;
        if (osMxBean instanceof com.sun.management.OperatingSystemMXBean sunBean) {
            rawCpu = sunBean.getProcessCpuLoad() * 100.0;
        }
        this.cpuUsagePercent = rawCpu < 0 ? 0 : rawCpu;

        // TPS must be collected on the main thread via Paper API
        Bukkit.getScheduler().runTask(plugin, () -> {
            double[] tpsArray = Bukkit.getTPS();
            this.currentTps = tpsArray.length > 0 ? Math.min(20.0, tpsArray[0]) : 20.0;

            // Update running stats
            sampleCount++;
            totalTps += (long) currentTps;
            if (currentTps < minTps) minTps = currentTps;
            if (currentTps > maxTps) maxTps = currentTps;
            avgTps = (double) totalTps / sampleCount;

            // Record history for panel charts
            tpsHistory.addLast(currentTps);
            if (tpsHistory.size() > HISTORY_CAP) tpsHistory.removeFirst();
            ramHistory.addLast(usedRamMb);
            if (ramHistory.size() > HISTORY_CAP) ramHistory.removeFirst();
            cpuHistory.addLast(cpuUsagePercent);
            if (cpuHistory.size() > HISTORY_CAP) cpuHistory.removeFirst();

            // Publish metrics update event
            eventBus.publish(EventBus.EVENT_METRICS_UPDATE, java.util.Map.of(
                    "tps", currentTps,
                    "cpu", cpuUsagePercent,
                    "ramUsed", usedRamMb,
                    "ramTotal", totalRamMb
            ));

            // Check thresholds and take action if exceeded
            checkThresholds();
        });
    }

    /**
     * Checks performance thresholds and logs warnings if exceeded.
     * On sustained overload, non-critical modules with a high resource score are
     * auto-disabled to protect server stability. When metrics recover, they are restored.
     */
    private void checkThresholds() {
        boolean tpsLow = currentTps < tpsThreshold;
        boolean cpuHigh = maxCpuPercent > 0 && cpuUsagePercent > maxCpuPercent;
        boolean ramHigh = maxRamMb > 0 && usedRamMb > maxRamMb;
        boolean overloaded = tpsLow || cpuHigh || ramHigh;

        if (tpsLow) {
            throttledWarn("tps", "TPS below threshold: " +
                    String.format("%.1f", currentTps) + " (threshold: " + tpsThreshold + ")");
        }
        if (cpuHigh) {
            throttledWarn("cpu", "CPU usage exceeds threshold: " +
                    String.format("%.1f", cpuUsagePercent) + "% (max: " + maxCpuPercent + "%)");
        }
        if (ramHigh) {
            throttledWarn("ram", "RAM usage exceeds threshold: " +
                    usedRamMb + "MB (max: " + maxRamMb + "MB)");
        }

        if (!autoDisableEnabled) return;

        if (overloaded) {
            tryAutoDisable();
        } else if (reEnableOnRecovery && !autoDisabledModules.isEmpty()) {
            tryReEnable();
        }
    }

    /**
     * Disables the active modules whose resource usage score exceeds the configured
     * threshold, skipping the excluded list. Runs on the main thread.
     */
    private void tryAutoDisable() {
        if (System.currentTimeMillis() - lastAutoDisableAction < autoDisableCooldownMs) {
            return;
        }
        for (SecurityModule module : moduleManager.getAllModules().values()) {
            String key = normalizeName(module.getName());
            if (!moduleManager.isModuleActive(key)) continue;
            if (excludedModules.contains(key)) continue;
            double score = module.getResourceUsageScore();
            if (score < moduleScoreThreshold) continue;

            if (moduleManager.disableModule(key)) {
                autoDisabledModules.add(key);
                logger.warning("[PerformanceMonitor] Auto-disabled module '" + module.getName()
                        + "' (resource score: " + String.format("%.2f", score) + ").");
            }
        }
        lastAutoDisableAction = System.currentTimeMillis();
    }

    /**
     * Re-enables all modules that were auto-disabled once the server has recovered.
     */
    private void tryReEnable() {
        if (System.currentTimeMillis() - lastAutoDisableAction < autoDisableCooldownMs) {
            return;
        }
        for (String key : autoDisabledModules) {
            if (moduleManager.enableModule(key)) {
                logger.info("[PerformanceMonitor] Re-enabled module '" + key + "' after performance recovery.");
            }
        }
        autoDisabledModules.clear();
        lastAutoDisableAction = System.currentTimeMillis();
    }

    /**
     * Normalizes a module name to the internal registry key (lowercase, no dashes/spaces).
     *
     * @param name Module name
     * @return Normalized key
     */
    private static String normalizeName(String name) {
        return name.toLowerCase().replace("-", "").replace(" ", "");
    }

    /**
     * Logs a threshold warning at most once every {@link #THRESHOLD_WARN_INTERVAL_MS} per metric,
     * to avoid flooding the console on every monitoring cycle while the server stays overloaded.
     */
    private void throttledWarn(String metricKey, String message) {
        long now = System.currentTimeMillis();
        Long last = lastThresholdWarn.get(metricKey);
        if (last != null && now - last < THRESHOLD_WARN_INTERVAL_MS) return;
        lastThresholdWarn.put(metricKey, now);
        logger.warning("[PerformanceMonitor] " + message);
    }

    /**
     * Stops the monitoring task.
     */
    public void stop() {
        if (monitorTask != null && !monitorTask.isCancelled()) {
            monitorTask.cancel(false);
        }
        logger.info("[PerformanceMonitor] Stopped.");
    }

    // ============================================================
    // GETTERS for current metrics
    // ============================================================

    /** @return Current TPS (1-minute average, capped at 20) */
    public double getCurrentTps() { return currentTps; }

    /** @return Current JVM process CPU usage percentage (0-100) */
    public double getCpuUsagePercent() { return cpuUsagePercent; }

    /** @return Current JVM heap used in MB */
    public long getUsedRamMb() { return usedRamMb; }

    /** @return Maximum JVM heap in MB */
    public long getTotalRamMb() { return totalRamMb; }

    /** @return Minimum TPS recorded since startup */
    public double getMinTps() { return minTps; }

    /** @return Maximum TPS recorded since startup */
    public double getMaxTps() { return maxTps; }

    /** @return Average TPS since startup */
    public double getAvgTps() { return avgTps; }

    /** @return Whether TPS is currently below the configured threshold */
    public boolean isTpsLow() { return currentTps < tpsThreshold; }

    /** @return Recent TPS samples (oldest→newest), capped at {@link #HISTORY_CAP} */
    public java.util.List<Double> getTpsHistory() { return new java.util.ArrayList<>(tpsHistory); }

    /** @return Recent RAM-used samples in MB (oldest→newest), capped at {@link #HISTORY_CAP} */
    public java.util.List<Long> getRamHistory() { return new java.util.ArrayList<>(ramHistory); }

    /** @return Recent CPU-usage samples in percent (oldest→newest), capped at {@link #HISTORY_CAP} */
    public java.util.List<Double> getCpuHistory() { return new java.util.ArrayList<>(cpuHistory); }

    /**
     * Returns a formatted status summary for the /security status command.
     *
     * @return Formatted status string
     */
    public String getStatusSummary() {
        return String.format("TPS: %.1f (min: %.1f, avg: %.1f) | CPU: %.1f%% | RAM: %dMB / %dMB",
                currentTps, minTps, avgTps, cpuUsagePercent, usedRamMb, totalRamMb);
    }
}
