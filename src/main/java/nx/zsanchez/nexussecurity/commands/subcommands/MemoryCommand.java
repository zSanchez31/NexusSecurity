package nx.zsanchez.nexussecurity.commands.subcommands;

import nx.zsanchez.nexussecurity.NexusSecurity;
import nx.zsanchez.nexussecurity.core.MemoryWatchdog;
import nx.zsanchez.nexussecurity.modules.shield.Shield;
import nx.zsanchez.nexussecurity.util.MessageFormatter;
import org.bukkit.ChatColor;
import org.bukkit.command.CommandSender;

/**
 * Handles /security memory subcommand. Shows live JVM heap/non-heap usage, GC activity,
 * and NexusSecurity internal resource footprints (caches, thread pool, batch queue, bans).
 */
public class MemoryCommand {

    private final NexusSecurity plugin;

    public MemoryCommand(NexusSecurity plugin) {
        this.plugin = plugin;
    }

    public void execute(CommandSender sender, String[] args) {
        MemoryWatchdog watchdog = plugin.getMemoryWatchdog();
        MemoryWatchdog.MemoryStats stats = watchdog.getStats();

        sender.sendMessage(MessageFormatter.header("NexusSecurity — Memoria JVM"));

        ChatColor levelColor = switch (watchdog.getCurrentLevel()) {
            case OK -> ChatColor.GREEN;
            case WARNING -> ChatColor.YELLOW;
            case CRITICAL -> ChatColor.RED;
        };
        sender.sendMessage(MessageFormatter.keyValue("Estado",
                levelColor + "● " + watchdog.getCurrentLevel().name()));

        if (stats != null) {
            double usedMb = stats.heapUsedBytes() / 1048576.0;
            double maxMb = stats.heapMaxBytes() / 1048576.0;
            double committedMb = stats.heapCommittedBytes() / 1048576.0;
            double nonHeapMb = stats.nonHeapUsedBytes() / 1048576.0;

            sender.sendMessage(MessageFormatter.separator());
            sender.sendMessage(ChatColor.AQUA + "Heap:");
            sender.sendMessage(MessageFormatter.keyValue("  Usado",
                    String.format("%.1f MB (%.1f%%)", usedMb, stats.heapUsedPercent())));
            sender.sendMessage(MessageFormatter.keyValue("  Comprometido", String.format("%.1f MB", committedMb)));
            sender.sendMessage(MessageFormatter.keyValue("  Máximo", String.format("%.1f MB", maxMb)));
            sender.sendMessage(MessageFormatter.keyValue("  Non-Heap", String.format("%.1f MB", nonHeapMb)));

            sender.sendMessage(ChatColor.AQUA + "Garbage Collection:");
            sender.sendMessage(MessageFormatter.keyValue("  Colecciones totales", String.valueOf(stats.gcCount())));
            sender.sendMessage(MessageFormatter.keyValue("  Tiempo GC total", stats.gcTimeMillis() + " ms"));
            sender.sendMessage(MessageFormatter.keyValue("  Δ colecciones (ciclo)",
                    String.valueOf(stats.gcCountDelta())));
        }

        sender.sendMessage(MessageFormatter.separator());
        sender.sendMessage(ChatColor.AQUA + "Recursos internos de NexusSecurity:");
        sender.sendMessage(MessageFormatter.keyValue("  Cachés", plugin.getCacheManager().getStats()));
        sender.sendMessage(MessageFormatter.keyValue("  Thread pool", plugin.getThreadPoolManager().getStats()));
        sender.sendMessage(MessageFormatter.keyValue("  Batch queue",
                plugin.getBatchWriter().getQueueSize() + " eventos"));

        Shield shield = plugin.getModuleManager().getModule("shield", Shield.class);
        if (shield != null) {
            sender.sendMessage(MessageFormatter.keyValue("  IPs baneadas (rate-limit)",
                    String.valueOf(shield.getRateLimiter().getBannedCount())));
        }

        sender.sendMessage(MessageFormatter.separator());
        sender.sendMessage(ChatColor.GRAY + "Umbrales: " + String.join(", ", watchdog.getThresholdSummary()));
    }
}
