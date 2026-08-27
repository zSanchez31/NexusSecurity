package nx.zsanchez.nexussecurity.modules.guardian;

import nx.zsanchez.nexussecurity.NexusSecurity;
import nx.zsanchez.nexussecurity.core.DatabaseManager;
import nx.zsanchez.nexussecurity.util.HashUtil;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

/**
 * Computes and manages SHA-256 integrity baselines for server plugins and critical files.
 */
public class IntegrityHasher {

    private final NexusSecurity plugin;
    private final Logger logger;
    private final DatabaseManager databaseManager;

    public IntegrityHasher(NexusSecurity plugin, DatabaseManager databaseManager) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
        this.databaseManager = databaseManager;
    }

    /**
     * Builds or updates the baseline hash map for all JAR files in plugins directory.
     * Async operation.
     *
     * @return Map of relative path -> SHA256 hash
     */
    public Map<String, String> generateBaseline() {
        Map<String, String> baseline = new HashMap<>();
        File pluginsDir = plugin.getDataFolder().getParentFile();
        if (pluginsDir == null || !pluginsDir.exists()) return baseline;

        File[] files = pluginsDir.listFiles((dir, name) -> name.endsWith(".jar"));
        if (files == null) return baseline;

        for (File file : files) {
            Path path = file.toPath();
            String hash = HashUtil.sha256File(path);
            if (!hash.isEmpty()) {
                baseline.put(file.getName(), hash);
                databaseManager.saveFileHash(path.toAbsolutePath().toString(), hash, file.length());
            }
        }
        logger.info("[IntegrityHasher] Generated baseline for " + baseline.size() + " plugin files.");
        return baseline;
    }

    /**
     * Verifies current plugin file hashes against the database baseline.
     *
     * @return Map of modified file name -> expected hash
     */
    public Map<String, String> verifyIntegrity() {
        Map<String, String> modifiedFiles = new HashMap<>();
        File pluginsDir = plugin.getDataFolder().getParentFile();
        if (pluginsDir == null || !pluginsDir.exists()) return modifiedFiles;

        File[] files = pluginsDir.listFiles((dir, name) -> name.endsWith(".jar"));
        if (files == null) return modifiedFiles;

        for (File file : files) {
            Path path = file.toPath();
            String currentHash = HashUtil.sha256File(path);
            String storedHash = databaseManager.getFileHash(path.toAbsolutePath().toString());

            if (storedHash != null && !storedHash.equalsIgnoreCase(currentHash)) {
                modifiedFiles.put(file.getName(), storedHash);
            }
        }
        return modifiedFiles;
    }
}
