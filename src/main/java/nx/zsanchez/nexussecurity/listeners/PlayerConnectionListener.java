package nx.zsanchez.nexussecurity.listeners;

import nx.zsanchez.nexussecurity.NexusSecurity;
import nx.zsanchez.nexussecurity.core.SecurityModule;
import nx.zsanchez.nexussecurity.modules.shield.Shield;
import nx.zsanchez.nexussecurity.util.MessageFormatter;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.event.player.PlayerQuitEvent;

import java.util.UUID;

/**
 * Listens to player pre-login, join, and quit events for Shield checks and HackDetector cleanup.
 */
public class PlayerConnectionListener implements Listener {

    private final NexusSecurity plugin;

    public PlayerConnectionListener(NexusSecurity plugin) {
        this.plugin = plugin;
    }

    @EventHandler(priority = EventPriority.HIGHEST, ignoreCancelled = true)
    public void onPreLogin(AsyncPlayerPreLoginEvent event) {
        String ip = event.getAddress().getHostAddress();

        // 1. Emergency mode check
        var autopilot = plugin.getModuleManager().getModule("autopilot", nx.zsanchez.nexussecurity.modules.autopilot.Autopilot.class);
        if (autopilot != null && autopilot.getEmergencyMode().isBlockNewConnections()) {
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER,
                    MessageFormatter.critical("El servidor está en MODO DE EMERGENCIA. Conexiones bloqueadas."));
            return;
        }

        // 2. Shield firewall & AntiVPN checks (Async)
        Shield shield = plugin.getModuleManager().getModule("shield", Shield.class);
        if (shield != null && shield.isEnabled()) {
            // Simulated dummy Player for permission check or IP check
            Shield.ConnectionCheckResult result = shield.checkConnection(null, ip);
            if (result.isBlocked()) {
                event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER,
                        MessageFormatter.colorize("&c[NexusSecurity] " + result.blockReason()));
            }
        }
    }

    @EventHandler
    public void onPlayerJoin(PlayerJoinEvent event) {
        logConnection(event.getPlayer(), "CONNECT", "SUCCESS");
    }

    @EventHandler
    public void onPlayerQuit(PlayerQuitEvent event) {
        // Centralized per-player cleanup: every module releases its tracked state for this UUID.
        UUID uuid = event.getPlayer().getUniqueId();
        for (SecurityModule module : plugin.getModuleManager().getAllModules().values()) {
            try {
                module.onPlayerQuit(uuid);
            } catch (Exception e) {
                plugin.getLogger().warning("[PlayerConnectionListener] onPlayerQuit failed for module "
                        + module.getName() + ": " + e.getMessage());
            }
        }
        logConnection(event.getPlayer(), "DISCONNECT", "SUCCESS");
    }

    /**
     * Logs a connection/disconnection to the compliance audit trail (async).
     *
     * @param player The player
     * @param action "CONNECT" or "DISCONNECT"
     * @param result Audit result
     */
    private void logConnection(org.bukkit.entity.Player player, String action, String result) {
        var compliance = plugin.getModuleManager().getModule("compliance", nx.zsanchez.nexussecurity.modules.compliance.Compliance.class);
        if (compliance == null || !compliance.isEnabled()) return;
        var auditLogger = compliance.getAuditLogger();
        if (!auditLogger.isLogConnections()) return;

        String playerName = player.getName();
        String ip = player.getAddress() != null
                ? player.getAddress().getAddress().getHostAddress() : "UNKNOWN";
        String actorType = player.isOp() || player.hasPermission("nexussecurity.admin") ? "ADMIN" : "PLAYER";
        plugin.getThreadPoolManager().submit("Compliance-Audit",
                () -> auditLogger.logAction(playerName, actorType, action, "server", result, ip));
    }
}
