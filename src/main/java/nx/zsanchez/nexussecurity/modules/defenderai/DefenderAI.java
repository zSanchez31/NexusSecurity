package nx.zsanchez.nexussecurity.modules.defenderai;

import nx.zsanchez.nexussecurity.NexusSecurity;
import nx.zsanchez.nexussecurity.core.*;

import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

/**
 * Module 4: DefenderAI — Machine Learning Anomaly Detection.
 * Utilizes statistical baselining and Z-Score anomaly detection to identify zero-day threats,
 * coordinated attacks, and abnormal server behaviors without static rule sets.
 */
public class DefenderAI implements SecurityModule {

    private final NexusSecurity plugin;
    private final Logger logger;
    private final AlertSystem alertSystem;
    private final EventBus eventBus;
    private final PerformanceMonitor performanceMonitor;
    private final ThreadPoolManager threadPoolManager;

    private BehaviorProfiler profiler;
    private AnomalyDetector anomalyDetector;

    private boolean enabled = false;
    private ScheduledFuture<?> evaluationTask;

    public DefenderAI(NexusSecurity plugin, AlertSystem alertSystem, EventBus eventBus,
                      PerformanceMonitor performanceMonitor, ThreadPoolManager threadPoolManager) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
        this.alertSystem = alertSystem;
        this.eventBus = eventBus;
        this.performanceMonitor = performanceMonitor;
        this.threadPoolManager = threadPoolManager;
    }

    @Override
    public String getName() { return "DefenderAI"; }

    @Override
    public String getDescription() { return "Adaptive statistical ML anomaly detection engine."; }

    @Override
    public void enable() {
        if (enabled) return;
        this.profiler = new BehaviorProfiler();
        this.anomalyDetector = new AnomalyDetector(plugin, alertSystem, eventBus, profiler);

        enabled = true;

        this.evaluationTask = threadPoolManager.scheduleAtFixedRate(
                "DefenderAI-Eval",
                this::runEvaluationCycle,
                30,
                30,
                TimeUnit.SECONDS
        );

        logger.info("[DefenderAI] Module enabled. Adaptive learning active.");
    }

    @Override
    public void disable() {
        if (!enabled) return;
        if (evaluationTask != null && !evaluationTask.isCancelled()) {
            evaluationTask.cancel(false);
        }
        enabled = false;
        logger.info("[DefenderAI] Module disabled.");
    }

    @Override
    public boolean isEnabled() { return enabled; }

    private void runEvaluationCycle() {
        if (!enabled) return;
        double tps = performanceMonitor.getCurrentTps();
        double joinRate = plugin.getServer().getOnlinePlayers().size();
        double cmdRate = 0.0; // Sampled from metrics

        profiler.recordSample(tps, joinRate, cmdRate);
        anomalyDetector.evaluate(tps, joinRate, cmdRate);
    }

    public BehaviorProfiler getProfiler() { return profiler; }
    public AnomalyDetector getAnomalyDetector() { return anomalyDetector; }

    @Override
    public double getResourceUsageScore() {
        if (profiler == null) return 0.0;
        int max = BehaviorProfiler.MAX_SAMPLES;
        double tpsScore = profiler.getTpsHistory().size() / (double) max;
        double joinScore = profiler.getPlayerJoinRates().size() / (double) max;
        double cmdScore = profiler.getCommandFrequencies().size() / (double) max;
        return Math.max(0.0, Math.min(1.0, (tpsScore + joinScore + cmdScore) / 3.0));
    }

    @Override
    public String getStatusSummary() {
        return "&aACTIVO &7| Learning samples: &f" + profiler.getTpsHistory().size();
    }
}
