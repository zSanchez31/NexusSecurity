package nx.zsanchez.nexussecurity.listeners;

import nx.zsanchez.nexussecurity.NexusSecurity;
import nx.zsanchez.nexussecurity.modules.compliance.AuditLogger;
import nx.zsanchez.nexussecurity.modules.compliance.Compliance;
import nx.zsanchez.nexussecurity.modules.hackdetector.HackDetector;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerCommandPreprocessEvent;

/**
 * Listens to player command executions for macro/bot analysis and immutable audit logging.
 */
public class PlayerInteractListener implements Listener {

    private final NexusSecurity plugin;

    public PlayerInteractListener(NexusSecurity plugin) {
        this.plugin = plugin;
    }

    @EventHandler(priority = EventPriority.MONITOR, ignoreCancelled = true)
    public void onCommand(PlayerCommandPreprocessEvent event) {
        String message = event.getMessage().substring(1); // Remove leading slash

        // HackDetector command check
        HackDetector hackDetector = plugin.getModuleManager().getModule("hackdetector", HackDetector.class);
        if (hackDetector != null && hackDetector.isEnabled()) {
            hackDetector.onCommand(event.getPlayer(), message);
        }

        // Compliance Audit logging (async — insertAuditLog performs blocking I/O)
        Compliance compliance = plugin.getModuleManager().getModule("compliance", Compliance.class);
        if (compliance != null && compliance.isEnabled()) {
            AuditLogger logger = compliance.getAuditLogger();
            boolean isAdmin = event.getPlayer().isOp() || event.getPlayer().hasPermission("nexussecurity.admin");
            boolean shouldLog = isAdmin ? logger.isLogAdminCommands() : logger.isLogPlayerCommands();
            if (shouldLog) {
                String playerName = event.getPlayer().getName();
                String ip = event.getPlayer().getAddress() != null
                        ? event.getPlayer().getAddress().getAddress().getHostAddress() : "UNKNOWN";
                String actorType = isAdmin ? "ADMIN" : "PLAYER";
                plugin.getThreadPoolManager().submit("Compliance-Audit", () ->
                        logger.logAction(playerName, actorType, "COMMAND", message, "SUCCESS", ip));
            }
        }
    }
}
