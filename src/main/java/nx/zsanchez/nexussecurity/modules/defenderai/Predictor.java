package nx.zsanchez.nexussecurity.modules.defenderai;

import java.util.ArrayList;
import java.util.List;

/**
 * Lightweight time-series predictor based on ordinary least squares linear regression.
 * Forecasts the next value of a metric and computes a prediction band from the residual
 * standard error, so anomalies can be flagged before they escalate.
 *
 * <p>All math is O(n) over the history window, safe to run on every evaluation cycle.</p>
 */
public final class Predictor {

    /** Minimal number of samples required to produce a meaningful forecast. */
    public static final int MIN_SAMPLES = 12;

    private Predictor() {}

    /**
     * Forecast for a metric history.
     *
     * @param predicted Value predicted for the next sample (index n)
     * @param slope     Regression slope (trend per sample)
     * @param rSquared  Goodness of fit (0.0 - 1.0)
     * @param residualStdDev Standard error of the residuals
     * @param upperBand Upper prediction bound for the next sample (predicted + margin * residualStdDev)
     */
    public record Forecast(double predicted, double slope, double rSquared,
                           double residualStdDev, double upperBand) {}

    /**
     * Fits a line y = a + b*x over the sample indices and predicts the next value.
     *
     * @param history Observed samples in chronological order
     * @param margin  How many residual standard deviations to include in the upper band
     * @return The forecast, or null if the history is too short
     */
    public static Forecast forecast(List<Double> history, double margin) {
        if (history == null || history.size() < MIN_SAMPLES) {
            return null;
        }
        int n = history.size();
        double sumX = 0, sumY = 0, sumXY = 0, sumX2 = 0;
        List<Double> snap;
        synchronized (history) {
            snap = new ArrayList<>(history);
        }
        for (int i = 0; i < n; i++) {
            double x = i;
            double y = snap.get(i);
            sumX += x;
            sumY += y;
            sumXY += x * y;
            sumX2 += x * x;
        }
        double denom = n * sumX2 - sumX * sumX;
        if (denom == 0.0) {
            return null;
        }
        double slope = (n * sumXY - sumX * sumY) / denom;
        double intercept = (sumY - slope * sumX) / n;

        // Next index
        double nextX = n;
        double predicted = intercept + slope * nextX;

        // Residual standard deviation (sample std of residuals)
        double sumResidualSq = 0;
        double meanY = sumY / n;
        double sumTotalSq = 0;
        for (int i = 0; i < n; i++) {
            double fitted = intercept + slope * i;
            double residual = snap.get(i) - fitted;
            sumResidualSq += residual * residual;
            double diff = snap.get(i) - meanY;
            sumTotalSq += diff * diff;
        }
        double residualStdDev = Math.sqrt(sumResidualSq / (n - 2));
        double rSquared = sumTotalSq == 0 ? 1.0 : 1.0 - (sumResidualSq / sumTotalSq);

        double upperBand = predicted + margin * residualStdDev;
        return new Forecast(predicted, slope, rSquared, residualStdDev, upperBand);
    }
}
