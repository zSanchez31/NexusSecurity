package nx.zsanchez.nexussecurity.modules.integrity;

import nx.zsanchez.nexussecurity.NexusSecurity;
import nx.zsanchez.nexussecurity.core.AlertSystem;
import nx.zsanchez.nexussecurity.core.DatabaseManager;
import nx.zsanchez.nexussecurity.util.HashUtil;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.logging.Logger;

/**
 * Monitors server.properties, spigot.yml, paper.yml, etc., for unauthorized file alterations.
 */
public class FileWatcher {

    private final NexusSecurity plugin;
    private final Logger logger;
    private final AlertSystem alertSystem;
    private final DatabaseManager databaseManager;

    private List<String> criticalFiles;
    private String modificationAction;

    public FileWatcher(NexusSecurity plugin, AlertSystem alertSystem, DatabaseManager databaseManager) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
        this.alertSystem = alertSystem;
        this.databaseManager = databaseManager;
        loadConfig();
    }

    public void loadConfig() {
        this.criticalFiles = plugin.getConfig().getStringList("modules.integrity.critical-files");
        this.modificationAction = plugin.getConfig().getString("modules.integrity.modification-action", "alert");
    }

    /**
     * Checks all critical configuration files against recorded SHA-256 baselines.
     */
    public void checkCriticalFiles() {
        Path serverRoot = plugin.getDataFolder().getParentFile().toPath();

        for (String fileRel : criticalFiles) {
            Path filePath = serverRoot.resolve(fileRel);
            if (!Files.exists(filePath)) continue;

            String currentHash = HashUtil.sha256File(filePath);
            String storedHash = databaseManager.getFileHash(filePath.toAbsolutePath().toString());

            if (storedHash == null) {
                // Record baseline if not set
                try {
                    databaseManager.saveFileHash(filePath.toAbsolutePath().toString(), currentHash, Files.size(filePath));
                } catch (Exception ignored) {}
            } else if (!storedHash.equalsIgnoreCase(currentHash)) {
                alertSystem.critical("Integrity", fileRel,
                        "CRITICAL CONFIG ALTERATION: " + fileRel + " hash changed! (Action: " + modificationAction + ")");
                plugin.getEventBus().publish(
                        nx.zsanchez.nexussecurity.core.EventBus.EVENT_FILE_MODIFIED,
                        java.util.Map.of("filePath", filePath.toAbsolutePath().toString(),
                                "expected", storedHash, "actual", currentHash));
            }
        }
    }
}
