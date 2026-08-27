package nx.zsanchez.nexussecurity.modules.vault;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import nx.zsanchez.nexussecurity.NexusSecurity;
import nx.zsanchez.nexussecurity.core.AlertSystem;
import nx.zsanchez.nexussecurity.core.ThreadPoolManager;

import java.io.*;
import java.nio.file.*;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/**
 * Handles creation, compression, optional AES-256 encryption, and rotation of server backups.
 *
 * <p>Backups can be {@code FULL} (baseline, all configured directories) or {@code INCREMENTAL}
 * (only files changed since the last full backup). Each archive embeds a
 * {@code __nexus_manifest.json} entry that identifies its type and, for incremental archives,
 * the base full backup it must be applied on top of during restore.</p>
 */
public class BackupScheduler {

    private static final String MANIFEST_ENTRY = "__nexus_manifest.json";
    private static final String STATE_FILE = "nexus-vault-state.json";

    private final NexusSecurity plugin;
    private final AlertSystem alertSystem;
    private final ThreadPoolManager threadPoolManager;
    private final Gson gson = new Gson();

    private String backupDir;
    private int retentionDays;
    private boolean encrypt;
    private String encryptionPassword;
    private List<String> includeDirs;
    private boolean incremental;
    private int fullBackupEvery;
    private volatile boolean backupInProgress;

    public BackupScheduler(NexusSecurity plugin, AlertSystem alertSystem, ThreadPoolManager threadPoolManager) {
        this.plugin = plugin;
        this.alertSystem = alertSystem;
        this.threadPoolManager = threadPoolManager;
        loadConfig();
    }

    public void loadConfig() {
        this.backupDir = plugin.getConfig().getString("modules.vault.backup-dir", "nexus-backups");
        this.retentionDays = plugin.getConfig().getInt("modules.vault.retention-days", 30);
        this.encrypt = plugin.getConfig().getBoolean("modules.vault.encrypt", true);
        this.encryptionPassword = plugin.getConfig().getString("modules.vault.encryption-password", "CHANGE_ME");
        this.includeDirs = plugin.getConfig().getStringList("modules.vault.include-dirs");
        this.incremental = plugin.getConfig().getBoolean("modules.vault.incremental", true);
        this.fullBackupEvery = Math.max(1, plugin.getConfig().getInt("modules.vault.full-backup-every", 7));
    }

    /**
     * Executes a backup of configured directories asynchronously.
     * Chooses FULL or INCREMENTAL automatically based on the state of the backup folder.
     */
    public void performBackupNow() {
        threadPoolManager.submit("VaultBackup", this::performBackupSync);
    }

    /**
     * Synchronous backup routine (must run off the main thread).
     */
    private void performBackupSync() {
        backupInProgress = true;
        try {
            File targetFolder = getBackupFolder();
            VaultState state = readState(targetFolder);

            boolean doFull = !incremental
                    || state.lastFullBackupFile == null
                    || state.backupsSinceFull >= fullBackupEvery;

            String timeStamp = new SimpleDateFormat("yyyy-MM-dd_HH-mm-ss").format(new Date());
            String fileName = "backup_" + timeStamp + (doFull ? "_full" : "_inc") + (encrypt ? ".enc" : ".zip");
            File backupFile = new File(targetFolder, fileName);

            alertSystem.info("Vault", "Backup",
                    "Starting " + (doFull ? "FULL" : "INCREMENTAL") + " backup: " + fileName);

            Path serverRoot = plugin.getDataFolder().getParentFile().toPath();
            ByteArrayOutputStream baos = new ByteArrayOutputStream();

            try (ZipOutputStream zos = new ZipOutputStream(baos)) {
                if (doFull) {
                    for (String dirName : includeDirs) {
                        Path dirPath = serverRoot.resolve(dirName);
                        if (Files.exists(dirPath)) {
                            zipDirectory(dirPath, dirName, zos);
                        }
                    }
                    writeManifest(zos, "FULL", null, null);
                } else {
                    long baselineTime = state.lastFullBackupTime;
                    List<String> changed = collectChangedFiles(serverRoot, baselineTime);
                    if (changed.isEmpty()) {
                        alertSystem.info("Vault", "Backup", "No file changes since last full backup; skipping incremental.");
                        return;
                    }
                    for (String rel : changed) {
                        addSingleFile(zos, serverRoot, rel);
                    }
                    writeManifest(zos, "INCREMENTAL", state.lastFullBackupFile, changed);
                }
            }

            byte[] zipBytes = baos.toByteArray();

            if (encrypt) {
                try (ByteArrayInputStream bais = new ByteArrayInputStream(zipBytes);
                     FileOutputStream fos = new FileOutputStream(backupFile)) {
                    BackupEncryptor.encrypt(bais, fos, encryptionPassword);
                }
            } else {
                Files.write(backupFile.toPath(), zipBytes);
            }

            // Update backup state metadata
            state.backupsSinceFull = doFull ? 0 : state.backupsSinceFull + 1;
            if (doFull) {
                state.lastFullBackupFile = fileName;
                state.lastFullBackupTime = System.currentTimeMillis();
            }
            VaultBackupEntry entry = new VaultBackupEntry();
            entry.file = fileName;
            entry.type = doFull ? "FULL" : "INCREMENTAL";
            entry.createdAt = System.currentTimeMillis();
            entry.size = backupFile.length();
            entry.baseFile = doFull ? null : state.lastFullBackupFile;
            state.backups.removeIf(e -> e.file.equals(fileName));
            state.backups.add(entry);
            writeState(targetFolder, state);

            alertSystem.info("Vault", "Backup",
                    "Backup completed: " + fileName + " (" + (backupFile.length() / (1024 * 1024)) + "MB, "
                            + (doFull ? "FULL" : "INCREMENTAL") + ")");

            rotateOldBackups(targetFolder);

        } catch (Exception e) {
            alertSystem.critical("Vault", "Backup", "Backup creation failed: " + e.getMessage());
        } finally {
            backupInProgress = false;
        }
    }

    /** @return true while a backup is being created */
    public boolean isBackupInProgress() { return backupInProgress; }

    /**
     * Lists available backup files (newest first) for the web panel.
     *
     * @return List of rows with name, size, modified, type
     */
    public java.util.List<java.util.Map<String, Object>> listBackupDetails() {
        java.util.List<java.util.Map<String, Object>> out = new java.util.ArrayList<>();
        File dir = getBackupFolder();
        File[] files = dir.listFiles((d, name) -> name.endsWith(".zip") || name.endsWith(".enc"));
        if (files != null) {
            java.util.Arrays.sort(files, java.util.Comparator.comparingLong(File::lastModified).reversed());
            for (File f : files) {
                java.util.Map<String, Object> m = new java.util.LinkedHashMap<>();
                m.put("name", f.getName());
                m.put("size", f.length());
                m.put("modified", f.lastModified());
                m.put("type", f.getName().contains("_full") ? "FULL" : (f.getName().contains("_inc") ? "INC" : "?"));
                out.add(m);
            }
        }
        return out;
    }

    // ============================================================
    // RESTORE
    // ============================================================

    /**
     * Outcome of a restore operation, with per-file results.
     */
    public record RestoreOutcome(boolean success, List<String> restored, List<String> failed, String summary) {}

    /**
     * Restores a backup file (name as listed in the backup folder).
     * Incremental backups are applied on top of their base full backup.
     * Must be called from an async thread.
     *
     * @param fileName Backup file name inside the backup directory
     * @return The outcome of the restore
     */
    public RestoreOutcome restoreBackup(String fileName) {
        File backupFile = new File(getBackupFolder(), fileName);
        if (!backupFile.exists() || backupFile.isDirectory()) {
            return new RestoreOutcome(false, List.of(), List.of(),
                    "Backup no encontrado: " + fileName);
        }

        List<String> restored = new ArrayList<>();
        List<String> failed = new ArrayList<>();

        try {
            String type = readType(backupFile);
            if ("INCREMENTAL".equals(type)) {
                // Prefer the exact base recorded in the manifest, fall back to the most recent FULL
                String baseName = readManifestBaseFile(backupFile);
                if (baseName == null || baseName.isBlank()) {
                    VaultState state = readState(getBackupFolder());
                    for (VaultBackupEntry entry : state.backups) {
                        if (entry.type.equals("FULL") && entry.baseFile == null) {
                            baseName = entry.file;
                            break;
                        }
                    }
                }
                if (baseName == null || baseName.isBlank()) {
                    return new RestoreOutcome(false, List.of(), List.of(),
                            "Backup incremental sin base FULL disponible. Restaura primero un backup FULL.");
                }
                File baseFile = new File(getBackupFolder(), baseName);
                if (!baseFile.exists()) {
                    return new RestoreOutcome(false, List.of(), List.of(),
                            "Base FULL " + baseName + " no encontrada en el directorio de backups.");
                }
                RestoreOutcome baseOutcome = extractBackup(baseFile, restored, failed);
                if (!baseOutcome.success) {
                    return baseOutcome;
                }
            }

            RestoreOutcome outcome = extractBackup(backupFile, restored, failed);
            if (outcome.success) {
                alertSystem.info("Vault", "Restore",
                        "Backup restaurado: " + fileName + " (" + restored.size() + " archivos, " + failed.size() + " fallidos)");
            }
            return outcome;
        } catch (Exception e) {
            plugin.getLogger().severe("[Vault] Restore failed for " + fileName + ": " + e.getMessage());
            return new RestoreOutcome(false, restored, failed, "Restore fallido: " + e.getMessage());
        }
    }

    private RestoreOutcome extractBackup(File backupFile, List<String> restored, List<String> failed) throws Exception {
        Path serverRoot = plugin.getDataFolder().getParentFile().toPath();
        try (ZipInputStream zis = openBackupStream(backupFile)) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                if (entry.isDirectory() || entry.getName().equals(MANIFEST_ENTRY)) {
                    zis.closeEntry();
                    continue;
                }
                Path target = serverRoot.resolve(entry.getName()).normalize();
                // Zip-slip protection: never write outside the server root
                if (!target.startsWith(serverRoot)) {
                    failed.add(entry.getName() + " (ruta fuera de la raíz)");
                    zis.closeEntry();
                    continue;
                }
                try {
                    Files.createDirectories(target.getParent());
                    Files.copy(zis, target, StandardCopyOption.REPLACE_EXISTING);
                    restored.add(entry.getName());
                } catch (Exception e) {
                    failed.add(entry.getName() + " (" + e.getMessage() + ")");
                }
                zis.closeEntry();
            }
        }
        return new RestoreOutcome(failed.isEmpty(), restored, failed,
                "Restaurados " + restored.size() + " archivos" + (failed.isEmpty() ? "" : ", fallidos: " + failed.size()));
    }

    private ZipInputStream openBackupStream(File backupFile) throws Exception {
        InputStream raw = new FileInputStream(backupFile);
        if (encrypt && backupFile.getName().endsWith(".enc")) {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            BackupEncryptor.decrypt(raw, bos, encryptionPassword);
            return new ZipInputStream(new ByteArrayInputStream(bos.toByteArray()));
        }
        return new ZipInputStream(raw);
    }

    /**
     * Reads the manifest type of a backup without restoring it.
     *
     * @param backupFile Backup file
     * @return "FULL", "INCREMENTAL", or "UNKNOWN"
     */
    private String readType(File backupFile) {
        VaultState state = readState(getBackupFolder());
        for (VaultBackupEntry entry : state.backups) {
            if (entry.file.equals(backupFile.getName())) {
                return entry.type;
            }
        }
        JsonObject manifest = readManifest(backupFile);
        return manifest != null && manifest.has("type") ? manifest.get("type").getAsString() : "UNKNOWN";
    }

    /**
     * Reads the base full backup referenced by an incremental archive's manifest.
     *
     * @param backupFile Backup file
     * @return Base file name, or null if not an incremental backup / manifest missing
     */
    private String readManifestBaseFile(File backupFile) {
        JsonObject manifest = readManifest(backupFile);
        if (manifest != null && manifest.has("baseFile")) {
            return manifest.get("baseFile").getAsString();
        }
        return null;
    }

    private JsonObject readManifest(File backupFile) {
        try (ZipInputStream zis = openBackupStream(backupFile)) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                if (entry.getName().equals(MANIFEST_ENTRY)) {
                    return gson.fromJson(new String(zis.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8), JsonObject.class);
                }
                zis.closeEntry();
            }
        } catch (Exception ignored) {}
        return null;
    }

    // ============================================================
    // LISTING
    // ============================================================

    /**
     * Returns the list of backups currently stored, newest first.
     *
     * @return Formatted lines for the command output
     */
    public List<String> listBackups() {
        List<String> lines = new ArrayList<>();
        VaultState state = readState(getBackupFolder());
        List<VaultBackupEntry> sorted = new ArrayList<>(state.backups);
        sorted.sort(Comparator.comparingLong((VaultBackupEntry e) -> e.createdAt).reversed());
        for (VaultBackupEntry entry : sorted) {
            String stamp = new SimpleDateFormat("yyyy-MM-dd HH:mm").format(new Date(entry.createdAt));
            lines.add(String.format("  %s  [%s]  %dMB  %s%s",
                    entry.file,
                    entry.type,
                    entry.size / (1024 * 1024),
                    stamp,
                    entry.baseFile != null ? " (base: " + entry.baseFile + ")" : ""));
        }
        return lines;
    }

    /**
     * Returns the backup directory path.
     *
     * @return Backup folder
     */
    public File getBackupFolder() {
        File folder = new File(plugin.getDataFolder().getParentFile(), backupDir);
        if (!folder.exists()) folder.mkdirs();
        return folder;
    }

    // ============================================================
    // INTERNAL HELPERS
    // ============================================================

    private void zipDirectory(Path folderPath, String parentName, ZipOutputStream zos) throws IOException {
        try (var stream = Files.walk(folderPath)) {
            stream.filter(p -> !Files.isDirectory(p)).forEach(path -> {
                String zipPath = parentName + "/" + folderPath.relativize(path).toString().replace("\\", "/");
                try {
                    addZipEntry(zos, zipPath, path);
                } catch (IOException ignored) {}
            });
        }
    }

    private void addSingleFile(ZipOutputStream zos, Path serverRoot, String relPath) throws IOException {
        Path path = serverRoot.resolve(relPath);
        if (Files.exists(path) && !Files.isDirectory(path)) {
            addZipEntry(zos, relPath, path);
        }
    }

    private void addZipEntry(ZipOutputStream zos, String zipPath, Path path) throws IOException {
        zos.putNextEntry(new ZipEntry(zipPath));
        Files.copy(path, zos);
        zos.closeEntry();
    }

    private List<String> collectChangedFiles(Path serverRoot, long baselineTime) throws IOException {
        List<String> changed = new ArrayList<>();
        for (String dirName : includeDirs) {
            Path dirPath = serverRoot.resolve(dirName);
            if (!Files.exists(dirPath)) continue;
            try (var stream = Files.walk(dirPath)) {
                stream.filter(p -> !Files.isDirectory(p)).forEach(path -> {
                    try {
                        if (Files.getLastModifiedTime(path).toMillis() > baselineTime) {
                            changed.add(dirName + "/" + dirPath.relativize(path).toString().replace("\\", "/"));
                        }
                    } catch (IOException ignored) {}
                });
            }
        }
        return changed;
    }

    private void writeManifest(ZipOutputStream zos, String type, String baseFile, List<String> changedFiles) throws IOException {
        JsonObject manifest = new JsonObject();
        manifest.addProperty("type", type);
        manifest.addProperty("createdAt", System.currentTimeMillis());
        if (baseFile != null) manifest.addProperty("baseFile", baseFile);
        if (changedFiles != null) {
            JsonArray array = new JsonArray();
            changedFiles.forEach(array::add);
            manifest.add("changedFiles", array);
        }
        zos.putNextEntry(new ZipEntry(MANIFEST_ENTRY));
        zos.write(manifest.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
        zos.closeEntry();
    }

    private void rotateOldBackups(File folder) {
        File[] files = folder.listFiles();
        if (files == null) return;
        long cutoff = System.currentTimeMillis() - (retentionDays * 86400000L);

        for (File f : files) {
            if (f.isFile() && !f.getName().equals(STATE_FILE) && f.lastModified() < cutoff) {
                f.delete();
                plugin.getLogger().info("[Vault] Purged expired backup: " + f.getName());
            }
        }
        // Keep a consistent state file after rotation
        writeState(folder, readState(folder));
    }

    // ============================================================
    // STATE FILE (backup metadata, never encrypted)
    // ============================================================

    private static class VaultBackupEntry {
        String file;
        String type;
        long createdAt;
        long size;
        String baseFile;
    }

    private static class VaultState {
        List<VaultBackupEntry> backups = new ArrayList<>();
        String lastFullBackupFile;
        long lastFullBackupTime;
        int backupsSinceFull;
    }

    private VaultState readState(File folder) {
        File stateFile = new File(folder, STATE_FILE);
        if (stateFile.exists()) {
            try (Reader reader = new FileReader(stateFile, java.nio.charset.StandardCharsets.UTF_8)) {
                VaultState state = gson.fromJson(reader, VaultState.class);
                if (state != null) {
                    if (state.backups == null) state.backups = new ArrayList<>();
                    return state;
                }
            } catch (Exception e) {
                plugin.getLogger().warning("[Vault] Could not read backup state file: " + e.getMessage());
            }
        }
        return new VaultState();
    }

    private void writeState(File folder, VaultState state) {
        File stateFile = new File(folder, STATE_FILE);
        try (Writer writer = new FileWriter(stateFile, java.nio.charset.StandardCharsets.UTF_8)) {
            gson.toJson(state, writer);
        } catch (Exception e) {
            plugin.getLogger().warning("[Vault] Could not write backup state file: " + e.getMessage());
        }
    }
}
