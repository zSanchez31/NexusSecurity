package nx.zsanchez.nexussecurity.core;

import com.sun.management.GarbageCollectorMXBean;
import nx.zsanchez.nexussecurity.NexusSecurity;

import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.MemoryUsage;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Logger;

/**
 * Proactive JVM memory watchdog for NexusSecurity.
 *
 * <p>Continuously samples heap and non-heap memory usage and garbage-collection activity,
 * emitting tiered {@code MEMORY WARNING} / {@code MEMORY CRITICAL} alerts when usage crosses the
 * configured thresholds. A small hysteresis window prevents alert storms during normal GC cycles,
 * and on a CRITICAL event an optional defensive {@link System#gc()} request is issued (rate-limited)
 * to recover memory before the server becomes unstable.</p>
 *
 * <p>All samples are published via the {@link EventBus} ({@link EventBus#EVENT_MEMORY_WARNING}) so
 * other modules (e.g. DefenderAI, Autopilot) can react, and the latest snapshot is exposed through
 * {@link #getStats()} for the {@code /security memory} command.</p>
 */
public class MemoryWatchdog {

    /** Severity level of the current memory situation. */
    public enum Level {
        /** Memory usage is below the warning threshold. */
        OK,
        /** Memory usage is at/above the warning threshold but below critical. */
        WARNING,
        /** Memory usage is at/above the critical threshold. */
        CRITICAL
    }

    /** Immutable snapshot of the last memory sample. */
    public record MemoryStats(
            long heapUsedBytes,
            long heapMaxBytes,
            long heapCommittedBytes,
            long nonHeapUsedBytes,
            long nonHeapCommittedBytes,
            double heapUsedPercent,
            long gcCount,
            long gcTimeMillis,
            long gcCountDelta,
            long gcTimeDeltaMillis
    ) {}

    private final NexusSecurity plugin;
    private final Logger logger;
    private final AlertSystem alertSystem;
    private final EventBus eventBus;
    private final MemoryMXBean memoryMxBean = ManagementFactory.getMemoryMXBean();

    private boolean enabled;
    private double warnPercent;
    private double criticalPercent;
    private boolean gcOnCritical;
    private long gcCooldownMs;

    private final AtomicLong lastGcCount = new AtomicLong(0);
    private final AtomicLong lastGcTime = new AtomicLong(0);

    private volatile Level currentLevel = Level.OK;
    private volatile MemoryStats latest;

    /**
     * Creates the memory watchdog and establishes the GC baseline counters.
     *
     * @param plugin      Main plugin instance
     * @param alertSystem Alert system for memory warnings
     * @param eventBus    Event bus for publishing memory events
     */
    public MemoryWatchdog(NexusSecurity plugin, AlertSystem alertSystem, EventBus eventBus) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
        this.alertSystem = alertSystem;
        this.eventBus = eventBus;
        loadConfig();

        long[] gc = readGc();
        lastGcCount.set(gc[0]);
        lastGcTime.set(gc[1]);
        this.latest = snapshot(gc[0], gc[1], 0, 0);
    }

    /**
     * Reloads memory watchdog configuration from config.yml.
     */
    public void loadConfig() {
        this.enabled = plugin.getConfig().getBoolean("performance.memory-watchdog.enabled", true);
        this.warnPercent = plugin.getConfig().getDouble("performance.memory-watchdog.warn-percent", 80.0);
        this.criticalPercent = plugin.getConfig().getDouble("performance.memory-watchdog.critical-percent", 92.0);
        this.gcOnCritical = plugin.getConfig().getBoolean("performance.memory-watchdog.gc-on-critical", true);
        this.gcCooldownMs = plugin.getConfig().getLong("performance.memory-watchdog.gc-cooldown-minutes", 15) * 60000L;
    }

    /**
     * Performs a single memory check: samples usage, updates the latest snapshot,
     * and emits an alert only when the severity level changes (hysteresis).
     * Safe to call from any thread.
     */
    public void check() {
        if (!enabled) return;

        MemoryUsage heap = memoryMxBean.getHeapMemoryUsage();
        MemoryUsage nonHeap = memoryMxBean.getNonHeapMemoryUsage();

        long used = heap.getUsed();
        long max = heap.getMax() > 0 ? heap.getMax() : heap.getCommitted();
        double percent = max > 0 ? (double) used / max * 100.0 : 0.0;

        long[] gc = readGc();
        long gcCountDelta = gc[0] - lastGcCount.getAndSet(gc[0]);
        long gcTimeDelta = gc[1] - lastGcTime.getAndSet(gc[1]);

        this.latest = snapshot(gc[0], gc[1], gcCountDelta, gcTimeDelta);

        Level level = percent >= criticalPercent ? Level.CRITICAL
                : percent >= warnPercent ? Level.WARNING : Level.OK;

        if (level != currentLevel) {
            currentLevel = level;
            double usedMb = used / 1048576.0;
            double maxMb = max / 1048576.0;
            switch (level) {
                case WARNING -> alertSystem.warning("MemoryWatchdog", "JVM",
                        String.format("Uso de memoria alto: %.1f%% (%.0f/%.0f MB)", percent, usedMb, maxMb));
                case CRITICAL -> {
                    alertSystem.critical("MemoryWatchdog", "JVM",
                            String.format("Uso de memoria CRÍTICO: %.1f%% (%.0f/%.0f MB)", percent, usedMb, maxMb));
                    requestGcIfNeeded();
                }
                case OK -> logger.info(String.format(
                        "[MemoryWatchdog] Memoria normalizada: %.1f%% (%.0f/%.0f MB)", percent, usedMb, maxMb));
            }
            eventBus.publish(EventBus.EVENT_MEMORY_WARNING, Map.of(
                    "level", level.name(),
                    "usedBytes", used,
                    "maxBytes", max,
                    "percent", percent,
                    "gcCountDelta", gcCountDelta
            ));
        }
    }

    /**
     * Requests a garbage collection when memory is CRITICAL, respecting a cooldown
     * so we don't thrash the JVM with repeated GC pauses.
     */
    private void requestGcIfNeeded() {
        if (!gcOnCritical) return;
        long now = System.currentTimeMillis();
        if (now - lastGcRequest >= gcCooldownMs) {
            lastGcRequest = now;
            logger.warning("[MemoryWatchdog] Memoria crítica: solicitando GC para recuperar espacio...");
            System.gc();
        }
    }

    private long lastGcRequest = 0;

    /**
     * Reads aggregate GC collection count and time across all collectors.
     * Values of -1 (unsupported) are treated as 0.
     *
     * @return A 2-element array: [totalCollectionCount, totalCollectionTimeMillis]
     */
    private long[] readGc() {
        long count = 0;
        long time = 0;
        for (var bean : ManagementFactory.getGarbageCollectorMXBeans()) {
            if (bean instanceof GarbageCollectorMXBean gc) {
                long c = gc.getCollectionCount();
                long t = gc.getCollectionTime();
                count += c < 0 ? 0 : c;
                time += t < 0 ? 0 : t;
            }
        }
        return new long[]{count, time};
    }

    /**
     * Builds an immutable snapshot from the current readings.
     */
    private MemoryStats snapshot(long gcCount, long gcTime, long gcCountDelta, long gcTimeDelta) {
        MemoryUsage heap = memoryMxBean.getHeapMemoryUsage();
        MemoryUsage nonHeap = memoryMxBean.getNonHeapMemoryUsage();
        long used = heap.getUsed();
        long max = heap.getMax() > 0 ? heap.getMax() : heap.getCommitted();
        double percent = max > 0 ? (double) used / max * 100.0 : 0.0;
        return new MemoryStats(
                used, max, heap.getCommitted(),
                nonHeap.getUsed(), nonHeap.getCommitted(),
                percent, gcCount, gcTime, gcCountDelta, gcTimeDelta
        );
    }

    /** @return The most recent memory snapshot (never null after construction). */
    public MemoryStats getStats() { return latest; }

    /** @return The current memory severity level. */
    public Level getCurrentLevel() { return currentLevel; }

    /** @return Whether the watchdog is enabled. */
    public boolean isEnabled() { return enabled; }

    /** @return Whether GC-on-critical is enabled (for diagnostics). */
    public boolean isGcOnCritical() { return gcOnCritical; }

    /** Exposed for the /security memory command convenience. */
    public List<String> getThresholdSummary() {
        return List.of(
                "warn-percent=" + warnPercent,
                "critical-percent=" + criticalPercent,
                "gc-on-critical=" + gcOnCritical
        );
    }
}
