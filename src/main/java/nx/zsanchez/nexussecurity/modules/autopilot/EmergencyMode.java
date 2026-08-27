package nx.zsanchez.nexussecurity.modules.autopilot;

import nx.zsanchez.nexussecurity.NexusSecurity;
import nx.zsanchez.nexussecurity.core.AlertSystem;
import nx.zsanchez.nexussecurity.modules.vault.Vault;
import nx.zsanchez.nexussecurity.util.MessageFormatter;
import org.bukkit.Bukkit;

import java.util.logging.Logger;

/**
 * Automates server emergency mode procedures when critical threats are declared.
 */
public class EmergencyMode {

    private final NexusSecurity plugin;
    private final Logger logger;
    private final AlertSystem alertSystem;

    private boolean active = false;
    private boolean blockNewConnections;
    private boolean initiateBackup;

    public EmergencyMode(NexusSecurity plugin, AlertSystem alertSystem) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
        this.alertSystem = alertSystem;
        loadConfig();
    }

    public void loadConfig() {
        this.blockNewConnections = plugin.getConfig().getBoolean("modules.autopilot.emergency-mode.actions.block-new-connections", true);
        this.initiateBackup = plugin.getConfig().getBoolean("modules.autopilot.emergency-mode.actions.initiate-backup", true);
    }

    /**
     * Activates emergency response protocol.
     */
    public synchronized void activate() {
        if (active) return;
        this.active = true;

        alertSystem.critical("Autopilot", "EmergencyMode", "🚨 EMERGENCY MODE ACTIVATED! Applying lockdown policies.");

        if (initiateBackup) {
            Vault vault = plugin.getModuleManager().getModule("vault", Vault.class);
            if (vault != null && vault.isEnabled()) {
                vault.getBackupScheduler().performBackupNow();
            }
        }

        Bukkit.getScheduler().runTask(plugin, () -> {
            String msg = MessageFormatter.critical("Modo de Emergencia Activado por NexusSecurity.");
            Bukkit.getOnlinePlayers().stream()
                    .filter(p -> p.hasPermission("nexussecurity.admin"))
                    .forEach(p -> p.sendMessage(msg));
        });
    }

    /**
     * Deactivates emergency response protocol.
     */
    public synchronized void deactivate() {
        if (!active) return;
        this.active = false;
        alertSystem.info("Autopilot", "EmergencyMode", "Emergency Mode deactivated. Server restored to normal operation.");
    }

    public boolean isActive() { return active; }
    public boolean isBlockNewConnections() { return active && blockNewConnections; }
}
