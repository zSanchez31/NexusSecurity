package nx.zsanchez.nexussecurity.modules.defenderai;

import nx.zsanchez.nexussecurity.NexusSecurity;
import nx.zsanchez.nexussecurity.core.AlertSystem;
import nx.zsanchez.nexussecurity.core.EventBus;

import java.util.Map;

/**
 * Evaluates current metrics against baseline using Z-Score statistical anomaly detection.
 * Z = (X - Mean) / StdDev. If |Z| > Threshold, an anomaly is declared.
 */
public class AnomalyDetector {

    private final NexusSecurity plugin;
    private final AlertSystem alertSystem;
    private final EventBus eventBus;
    private final BehaviorProfiler profiler;

    private double zScoreThreshold;
    private int criticalThreshold;
    private boolean predictionEnabled;
    private double predictionMargin;

    public AnomalyDetector(NexusSecurity plugin, AlertSystem alertSystem, EventBus eventBus, BehaviorProfiler profiler) {
        this.plugin = plugin;
        this.alertSystem = alertSystem;
        this.eventBus = eventBus;
        this.profiler = profiler;
        loadConfig();
    }

    public void loadConfig() {
        this.zScoreThreshold = plugin.getConfig().getDouble("modules.defender-ai.anomaly-threshold", 3.0);
        this.criticalThreshold = plugin.getConfig().getInt("modules.defender-ai.critical-threshold", 85);
        this.predictionEnabled = plugin.getConfig().getBoolean("modules.defender-ai.prediction-enabled", true);
        this.predictionMargin = plugin.getConfig().getDouble("modules.defender-ai.prediction-margin", 1.5);
    }

    /**
     * Analyzes current TPS, join rate, command rate for statistical anomalies.
     * Runs z-score detection and trend prediction on non-TPS metrics.
     */
    public void evaluate(double currentTps, double currentJoinRate, double currentCmdRate) {
        checkMetric("TPS", currentTps, profiler.getTpsHistory());
        checkMetric("PlayerJoinRate", currentJoinRate, profiler.getPlayerJoinRates());
        checkMetric("CommandFrequency", currentCmdRate, profiler.getCommandFrequencies());

        if (predictionEnabled) {
            predictMetric("PlayerJoinRate", currentJoinRate, profiler.getPlayerJoinRates());
            predictMetric("CommandFrequency", currentCmdRate, profiler.getCommandFrequencies());
        }
    }

    private void checkMetric(String metricName, double currentValue, java.util.List<Double> history) {
        double mean = profiler.getMean(history);
        double stdDev = profiler.getStdDev(history);

        if (stdDev == 0.0 || history.size() < 20) return; // Need minimal learning baseline

        double zScore = Math.abs(currentValue - mean) / stdDev;

        if (zScore >= zScoreThreshold) {
            int riskScore = (int) Math.min(100, (zScore / zScoreThreshold) * 50);
            alertSystem.warning("DefenderAI", metricName,
                    String.format("Statistical anomaly detected in %s: value=%.2f, mean=%.2f, zScore=%.2f (risk: %d/100)",
                            metricName, currentValue, mean, zScore, riskScore));

            eventBus.publish(EventBus.EVENT_ANOMALY_DETECTED, Map.of(
                    "metric", metricName,
                    "zScore", zScore,
                    "riskScore", riskScore
            ));
        }
    }

    /**
     * Predicts the next value of a metric via linear regression. If the current value is
     * rising above the predicted upper band (i.e. the trend is accelerating beyond normal),
     * an imminent-attack warning is raised so administrators can react preemptively.
     */
    private void predictMetric(String metricName, double currentValue, java.util.List<Double> history) {
        Predictor.Forecast forecast = Predictor.forecast(history, predictionMargin);
        if (forecast == null) return;

        // Only flag when the trend is positive (rising) and the current value breaches the band
        if (forecast.slope() <= 0 || currentValue <= forecast.upperBand()) return;

        int riskScore = (int) Math.min(100, 50 + (currentValue - forecast.upperBand())
                / Math.max(1e-9, Math.abs(forecast.upperBand())) * 25);
        alertSystem.warning("DefenderAI", metricName,
                String.format("Attack trend predicted in %s: value=%.2f exceeds forecast %.2f (slope=%.3f, r²=%.2f, risk: %d/100)",
                        metricName, currentValue, forecast.upperBand(), forecast.slope(), forecast.rSquared(), riskScore));

        eventBus.publish(EventBus.EVENT_ANOMALY_DETECTED, Map.of(
                "metric", metricName,
                "type", "PREDICTION",
                "slope", forecast.slope(),
                "predicted", forecast.predicted(),
                "riskScore", riskScore
        ));
    }
}
