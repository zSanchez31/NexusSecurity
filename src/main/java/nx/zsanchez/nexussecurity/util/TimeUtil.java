package nx.zsanchez.nexussecurity.util;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.TimeUnit;

/**
 * Utility class for time-related operations used across all NexusSecurity modules.
 * Provides human-readable duration formatting and timestamp utilities.
 */
public final class TimeUtil {

    /** Standard timestamp format used throughout the plugin. */
    public static final DateTimeFormatter TIMESTAMP_FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    /** Short date format for log file names. */
    public static final DateTimeFormatter DATE_FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd");

    private TimeUtil() {}

    /**
     * Returns the current timestamp as a formatted string.
     *
     * @return Current timestamp in "yyyy-MM-dd HH:mm:ss" format
     */
    public static String now() {
        return LocalDateTime.now().format(TIMESTAMP_FORMATTER);
    }

    /**
     * Returns the current date as a formatted string.
     *
     * @return Current date in "yyyy-MM-dd" format
     */
    public static String today() {
        return LocalDateTime.now().format(DATE_FORMATTER);
    }

    /**
     * Converts an epoch millis timestamp to a formatted string.
     *
     * @param epochMillis The epoch milliseconds
     * @return Formatted timestamp string
     */
    public static String format(long epochMillis) {
        return LocalDateTime.ofInstant(Instant.ofEpochMilli(epochMillis), ZoneId.systemDefault())
                .format(TIMESTAMP_FORMATTER);
    }

    /**
     * Returns a human-readable representation of a duration in milliseconds.
     * Examples: "2h 30m", "45s", "3d 2h"
     *
     * @param millis Duration in milliseconds
     * @return Human-readable duration string
     */
    public static String formatDuration(long millis) {
        if (millis < 0) return "N/A";
        long days = TimeUnit.MILLISECONDS.toDays(millis);
        long hours = TimeUnit.MILLISECONDS.toHours(millis) % 24;
        long minutes = TimeUnit.MILLISECONDS.toMinutes(millis) % 60;
        long seconds = TimeUnit.MILLISECONDS.toSeconds(millis) % 60;

        StringBuilder sb = new StringBuilder();
        if (days > 0) sb.append(days).append("d ");
        if (hours > 0) sb.append(hours).append("h ");
        if (minutes > 0) sb.append(minutes).append("m ");
        if (seconds > 0 || sb.isEmpty()) sb.append(seconds).append("s");
        return sb.toString().trim();
    }

    /**
     * Returns a human-readable representation of the time remaining until expiry.
     *
     * @param expiryEpochMillis The expiry timestamp in epoch milliseconds
     * @return Formatted remaining time, or "EXPIRED" if past
     */
    public static String timeUntil(long expiryEpochMillis) {
        long remaining = expiryEpochMillis - System.currentTimeMillis();
        if (remaining <= 0) return "EXPIRADO";
        return formatDuration(remaining);
    }

    /**
     * Checks if a given epoch timestamp is within the next N days.
     *
     * @param epochMillis The epoch milliseconds to check
     * @param days        Number of days to check against
     * @return true if the timestamp occurs within the next {@code days} days
     */
    public static boolean isWithinDays(long epochMillis, int days) {
        long now = System.currentTimeMillis();
        long threshold = now + TimeUnit.DAYS.toMillis(days);
        return epochMillis > now && epochMillis <= threshold;
    }

    /**
     * Converts minutes to ticks (Minecraft server ticks, 20 per second).
     *
     * @param minutes Minutes to convert
     * @return Number of ticks
     */
    public static long minutesToTicks(long minutes) {
        return minutes * 60 * 20;
    }

    /**
     * Converts seconds to ticks.
     *
     * @param seconds Seconds to convert
     * @return Number of ticks
     */
    public static long secondsToTicks(long seconds) {
        return seconds * 20;
    }

    /**
     * Returns the epoch milliseconds for N days ago.
     *
     * @param days Days in the past
     * @return Epoch milliseconds
     */
    public static long daysAgo(int days) {
        return System.currentTimeMillis() - TimeUnit.DAYS.toMillis(days);
    }

    /**
     * Returns the epoch milliseconds for N days in the future.
     *
     * @param days Days in the future
     * @return Epoch milliseconds
     */
    public static long daysFromNow(int days) {
        return System.currentTimeMillis() + TimeUnit.DAYS.toMillis(days);
    }
}
