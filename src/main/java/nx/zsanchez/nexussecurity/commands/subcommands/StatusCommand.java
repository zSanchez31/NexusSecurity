package nx.zsanchez.nexussecurity.commands.subcommands;

import nx.zsanchez.nexussecurity.NexusSecurity;
import nx.zsanchez.nexussecurity.api.model.SubscriptionResponse;
import nx.zsanchez.nexussecurity.core.MemoryWatchdog;
import nx.zsanchez.nexussecurity.util.MessageFormatter;
import nx.zsanchez.nexussecurity.util.TimeUtil;
import org.bukkit.ChatColor;
import org.bukkit.command.CommandSender;

import java.util.List;

/**
 * Handles /security status subcommand. Displays plugin status, active modules, TPS/RAM/CPU, and subscription info.
 */
public class StatusCommand {

    private final NexusSecurity plugin;

    public StatusCommand(NexusSecurity plugin) {
        this.plugin = plugin;
    }

    public void execute(CommandSender sender, String[] args) {
        sender.sendMessage(MessageFormatter.header("NexusSecurity — Status"));

        // Subscription info
        boolean active = plugin.getSubscriptionManager().isSubscriptionActive();
        SubscriptionResponse sub = plugin.getSubscriptionManager().getCurrentSubscription();

        String subStatus = active
                ? ChatColor.GREEN + "● ACTIVA (" + (sub != null ? sub.getPlan() : "VALIDATED") + ")"
                : ChatColor.RED + "● MODO LIMITADO (Inválida/Expirada)";

        sender.sendMessage(MessageFormatter.keyValue("Suscripción API", subStatus));

        if (sub != null && sub.getExpiresAt() > 0) {
            sender.sendMessage(MessageFormatter.keyValue("Expira en", TimeUtil.timeUntil(sub.getExpiresAt())));
        }

        // Performance info
        sender.sendMessage(MessageFormatter.separator());
        sender.sendMessage(ChatColor.AQUA + "Performance & Telemetría:");
        sender.sendMessage(MessageFormatter.keyValue("Rendimiento", plugin.getPerformanceMonitor().getStatusSummary()));

        MemoryWatchdog.Level memLevel = plugin.getMemoryWatchdog().getCurrentLevel();
        ChatColor memColor = switch (memLevel) {
            case OK -> ChatColor.GREEN;
            case WARNING -> ChatColor.YELLOW;
            case CRITICAL -> ChatColor.RED;
        };
        sender.sendMessage(MessageFormatter.keyValue("Memoria JVM",
                memColor + memLevel.name() + ChatColor.GRAY + " ("
                        + String.format("%.1f%% heap)", plugin.getMemoryWatchdog().getStats().heapUsedPercent())));

        // Modules status
        sender.sendMessage(MessageFormatter.separator());
        sender.sendMessage(ChatColor.AQUA + "Módulos de Seguridad (" +
                plugin.getModuleManager().getActiveModuleCount() + "/" +
                plugin.getModuleManager().getTotalModuleCount() + " activos):");

        List<String> moduleLines = plugin.getModuleManager().getStatusLines();
        for (String line : moduleLines) {
            sender.sendMessage(line);
        }

        sender.sendMessage(MessageFormatter.separator());
    }
}
