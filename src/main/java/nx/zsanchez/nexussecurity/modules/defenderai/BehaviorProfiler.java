package nx.zsanchez.nexussecurity.modules.defenderai;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Builds baseline statistics (mean and standard deviation) for server metrics
 * using Exponential Weighted Moving Average (EWMA) and standard statistical distributions.
 */
public class BehaviorProfiler {

    private final List<Double> tpsHistory = Collections.synchronizedList(new ArrayList<>());
    private final List<Double> playerJoinRates = Collections.synchronizedList(new ArrayList<>());
    private final List<Double> commandFrequencies = Collections.synchronizedList(new ArrayList<>());

    public static final int MAX_SAMPLES = 500;

    /**
     * Record a new metric sample.
     */
    public void recordSample(double tps, double joinRate, double cmdFreq) {
        addSample(tpsHistory, tps);
        addSample(playerJoinRates, joinRate);
        addSample(commandFrequencies, cmdFreq);
    }

    private void addSample(List<Double> list, double value) {
        synchronized (list) {
            list.add(value);
            if (list.size() > MAX_SAMPLES) {
                list.remove(0);
            }
        }
    }

    public double getMean(List<Double> samples) {
        synchronized (samples) {
            if (samples.isEmpty()) return 0.0;
            return samples.stream().mapToDouble(Double::doubleValue).average().orElse(0.0);
        }
    }

    public double getStdDev(List<Double> samples) {
        synchronized (samples) {
            if (samples.size() < 2) return 0.0;
            double mean = getMean(samples);
            double sumSquareDiff = samples.stream()
                    .mapToDouble(val -> Math.pow(val - mean, 2))
                    .sum();
            return Math.sqrt(sumSquareDiff / (samples.size() - 1));
        }
    }

    public List<Double> getTpsHistory() { return tpsHistory; }
    public List<Double> getPlayerJoinRates() { return playerJoinRates; }
    public List<Double> getCommandFrequencies() { return commandFrequencies; }
}
