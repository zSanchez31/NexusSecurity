package nx.zsanchez.nexussecurity.util;

import org.bukkit.ChatColor;

/**
 * Utility class for formatting messages with color codes and severity prefixes.
 * All NexusSecurity player/console messages pass through this class for consistency.
 */
public final class MessageFormatter {

    /** The prefix prepended to all NexusSecurity messages. */
    public static final String PREFIX = ChatColor.DARK_GRAY + "[" + ChatColor.AQUA + "NexusSecurity" + ChatColor.DARK_GRAY + "] " + ChatColor.RESET;

    private MessageFormatter() {}

    /**
     * Formats a plain message with the NexusSecurity prefix.
     *
     * @param message The message to format (supports '&amp;' color codes)
     * @return The fully formatted, color-translated message
     */
    public static String format(String message) {
        return PREFIX + colorize(message);
    }

    /**
     * Formats an INFO-level message (white text).
     *
     * @param message The message content
     * @return Formatted INFO message
     */
    public static String info(String message) {
        return PREFIX + ChatColor.GRAY + "[INFO] " + ChatColor.WHITE + colorize(message);
    }

    /**
     * Formats a WARNING-level message (yellow text).
     *
     * @param message The message content
     * @return Formatted WARNING message
     */
    public static String warning(String message) {
        return PREFIX + ChatColor.YELLOW + "[WARN] " + colorize(message);
    }

    /**
     * Formats a CRITICAL-level message (red text).
     *
     * @param message The message content
     * @return Formatted CRITICAL message
     */
    public static String critical(String message) {
        return PREFIX + ChatColor.RED + "[" + ChatColor.DARK_RED + "CRITICAL" + ChatColor.RED + "] " + colorize(message);
    }

    /**
     * Formats a SUCCESS message (green text).
     *
     * @param message The message content
     * @return Formatted SUCCESS message
     */
    public static String success(String message) {
        return PREFIX + ChatColor.GREEN + colorize(message);
    }

    /**
     * Formats an ERROR message (dark red text).
     *
     * @param message The message content
     * @return Formatted ERROR message
     */
    public static String error(String message) {
        return PREFIX + ChatColor.DARK_RED + colorize(message);
    }

    /**
     * Translates '&amp;' color codes to Bukkit's ChatColor format.
     *
     * @param message The message with '&amp;' codes
     * @return Color-translated string
     */
    public static String colorize(String message) {
        if (message == null) return "";
        return ChatColor.translateAlternateColorCodes('&', message);
    }

    /**
     * Strips all color codes from a message for plain text output.
     *
     * @param message The colored message
     * @return Plain text without color codes
     */
    public static String stripColors(String message) {
        if (message == null) return "";
        return ChatColor.stripColor(message);
    }

    /**
     * Creates a separator line for command outputs.
     *
     * @return A formatted separator line
     */
    public static String separator() {
        return ChatColor.DARK_GRAY + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━";
    }

    /**
     * Creates a formatted header line for command outputs.
     *
     * @param title The title to display
     * @return A formatted header
     */
    public static String header(String title) {
        return ChatColor.DARK_GRAY + "━━━━━ " + ChatColor.AQUA + ChatColor.BOLD + title + ChatColor.RESET + ChatColor.DARK_GRAY + " ━━━━━";
    }

    /**
     * Formats a key-value pair for status displays.
     *
     * @param key The label
     * @param value The value
     * @return Formatted "  key: value" string
     */
    public static String keyValue(String key, String value) {
        return ChatColor.GRAY + "  " + ChatColor.AQUA + key + ChatColor.DARK_GRAY + ": " + ChatColor.WHITE + value;
    }

    /**
     * Formats a module status line with enabled/disabled indicator.
     *
     * @param moduleName Module name
     * @param enabled Whether the module is active
     * @return Formatted status line
     */
    public static String moduleStatus(String moduleName, boolean enabled) {
        String status = enabled
                ? ChatColor.GREEN + "● ACTIVO"
                : ChatColor.RED + "● INACTIVO";
        return ChatColor.GRAY + "  " + ChatColor.WHITE + moduleName + " " + status;
    }
}
