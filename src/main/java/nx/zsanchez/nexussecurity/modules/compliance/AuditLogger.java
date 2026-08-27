package nx.zsanchez.nexussecurity.modules.compliance;

import nx.zsanchez.nexussecurity.NexusSecurity;
import nx.zsanchez.nexussecurity.core.DatabaseManager;

/**
 * Handles immutable logging of all administrative, player, and system actions into the database audit trail.
 */
public class AuditLogger {

    private final NexusSecurity plugin;
    private final DatabaseManager databaseManager;

    private boolean logAdminCommands;
    private boolean logPlayerCommands;
    private boolean logConnections;

    public AuditLogger(NexusSecurity plugin, DatabaseManager databaseManager) {
        this.plugin = plugin;
        this.databaseManager = databaseManager;
        loadConfig();
    }

    public void loadConfig() {
        this.logAdminCommands = plugin.getConfig().getBoolean("modules.compliance.log-admin-commands", true);
        this.logPlayerCommands = plugin.getConfig().getBoolean("modules.compliance.log-player-commands", true);
        this.logConnections = plugin.getConfig().getBoolean("modules.compliance.log-connections", true);
    }

    public void logAction(String actor, String actorType, String action, String target, String result, String ipAddress) {
        databaseManager.insertAuditLog(actor, actorType, action, target, result, ipAddress);
    }

    public boolean isLogAdminCommands() { return logAdminCommands; }
    public boolean isLogPlayerCommands() { return logPlayerCommands; }
    public boolean isLogConnections() { return logConnections; }
}
