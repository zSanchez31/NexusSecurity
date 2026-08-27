package nx.zsanchez.nexussecurity.modules.guardian;

import nx.zsanchez.nexussecurity.NexusSecurity;
import nx.zsanchez.nexussecurity.core.AlertSystem;
import nx.zsanchez.nexussecurity.core.CacheManager;
import nx.zsanchez.nexussecurity.util.HashUtil;

import java.io.File;
import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import java.util.logging.Logger;
import java.util.stream.Stream;

/**
 * Scans server files for suspicious content, new executables, and behavioral anomalies.
 * Uses SHA-256 hashing to detect file modifications and identifies suspicious class patterns.
 */
public class FileScanner {

    private final NexusSecurity plugin;
    private final Logger logger;
    private final AlertSystem alertSystem;
    private final CacheManager cacheManager;

    private List<String> monitoredDirs;
    private List<String> scanExtensions;
    private String suspiciousAction;
    private String quarantineDir;

    // Suspicious patterns in JAR manifests or class names
    private static final List<String> SUSPICIOUS_PATTERNS = List.of(
            "Runtime.exec", "ProcessBuilder", "getRuntime", "loadLibrary",
            "URLClassLoader", "defineClass", "Unsafe", "sun.misc"
    );

    /**
     * Creates the file scanner.
     *
     * @param plugin       Main plugin instance
     * @param alertSystem  Alert system
     * @param cacheManager Cache for file hashes
     */
    public FileScanner(NexusSecurity plugin, AlertSystem alertSystem, CacheManager cacheManager) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
        this.alertSystem = alertSystem;
        this.cacheManager = cacheManager;
        loadConfig();
    }

    /**
     * Loads file scanner configuration.
     */
    public void loadConfig() {
        this.monitoredDirs = plugin.getConfig().getStringList("modules.guardian.monitored-directories");
        this.scanExtensions = plugin.getConfig().getStringList("modules.guardian.scan-extensions");
        this.suspiciousAction = plugin.getConfig().getString("modules.guardian.suspicious-action", "alert");
        this.quarantineDir = plugin.getConfig().getString("modules.guardian.quarantine-dir", "nexus-quarantine");
    }

    /**
     * Performs a full scan of all monitored directories.
     * Must be called from an async thread.
     *
     * @return Number of suspicious files found
     */
    public int performFullScan() {
        int suspiciousCount = 0;
        Path serverRoot = plugin.getServer().getWorldContainer().toPath().getParent();
        if (serverRoot == null) serverRoot = plugin.getServer().getWorldContainer().toPath();

        for (String dir : monitoredDirs) {
            Path dirPath = dir.equals(".") ? serverRoot : serverRoot.resolve(dir);
            if (!Files.exists(dirPath)) continue;

            try (Stream<Path> files = Files.walk(dirPath)) {
                List<Path> fileList = files
                        .filter(Files::isRegularFile)
                        .filter(p -> hasMonitoredExtension(p.toString()))
                        .toList();

                for (Path file : fileList) {
                    if (scanFile(file)) {
                        suspiciousCount++;
                    }
                }
            } catch (IOException e) {
                logger.warning("[Guardian] Error scanning directory " + dirPath + ": " + e.getMessage());
            }
        }

        logger.info("[Guardian] Full scan complete. Found " + suspiciousCount + " suspicious file(s).");
        return suspiciousCount;
    }

    /**
     * Scans a single file for suspicious content.
     *
     * @param filePath Path to the file
     * @return true if file is suspicious
     */
    private boolean scanFile(Path filePath) {
        try {
            // Check cached hash — if unchanged, skip content analysis
            String currentHash = HashUtil.sha256File(filePath);
            String cachedHash = cacheManager.getFileHash(filePath.toString());

            if (currentHash.equals(cachedHash)) {
                return false; // Not changed since last check
            }
            cacheManager.putFileHash(filePath.toString(), currentHash);

            // For JARs, check for suspicious class patterns in the manifest/entries
            if (filePath.toString().endsWith(".jar")) {
                return scanJar(filePath);
            }

            // For scripts, check for suspicious content
            if (filePath.toString().endsWith(".sh") || filePath.toString().endsWith(".bat") ||
                    filePath.toString().endsWith(".py")) {
                return scanScript(filePath);
            }

        } catch (Exception e) {
            logger.fine("[Guardian] Error scanning file " + filePath + ": " + e.getMessage());
        }
        return false;
    }

    /**
     * Scans a JAR file for suspicious class entries or manifests.
     *
     * @param jarPath Path to JAR
     * @return true if suspicious
     */
    private boolean scanJar(Path jarPath) {
        try (java.util.jar.JarFile jar = new java.util.jar.JarFile(jarPath.toFile())) {
            java.util.jar.Manifest manifest = jar.getManifest();
            if (manifest != null) {
                String mainClass = manifest.getMainAttributes().getValue("Main-Class");
                if (mainClass != null) {
                    // Server plugins shouldn't have Main-Class attributes typically
                    alertSystem.warning("Guardian", jarPath.getFileName().toString(),
                            "JAR has Main-Class manifest entry (unusual for plugins): " + mainClass);
                }
            }

            // Check entry names for suspicious patterns
            jar.stream()
                    .filter(e -> e.getName().endsWith(".class"))
                    .forEach(e -> {
                        for (String pattern : SUSPICIOUS_PATTERNS) {
                            if (e.getName().contains(pattern.replace(".", "/"))) {
                                alertSystem.warning("Guardian", jarPath.getFileName().toString(),
                                        "Suspicious class detected: " + e.getName());
                            }
                        }
                    });
        } catch (Exception e) {
            logger.fine("[Guardian] Cannot scan JAR " + jarPath + ": " + e.getMessage());
        }
        return false;
    }

    /**
     * Scans a script file for suspicious content.
     *
     * @param scriptPath Path to script
     * @return true if suspicious
     */
    private boolean scanScript(Path scriptPath) {
        try {
            String content = Files.readString(scriptPath);
            List<String> scriptSuspicious = List.of("curl", "wget", "nc ", "ncat", "/dev/tcp", "base64 -d");
            for (String pattern : scriptSuspicious) {
                if (content.contains(pattern)) {
                    alertSystem.critical("Guardian", scriptPath.getFileName().toString(),
                            "Suspicious script content detected: contains '" + pattern + "'");
                    if (suspiciousAction.equals("quarantine")) {
                        quarantineFile(scriptPath);
                    }
                    return true;
                }
            }
        } catch (IOException e) {
            logger.fine("[Guardian] Cannot read script " + scriptPath + ": " + e.getMessage());
        }
        return false;
    }

    /**
     * Moves a file to the quarantine directory.
     *
     * @param filePath File to quarantine
     */
    private void quarantineFile(Path filePath) {
        try {
            File quarantine = new File(plugin.getDataFolder().getParent(), quarantineDir);
            quarantine.mkdirs();
            Path dest = quarantine.toPath().resolve(filePath.getFileName() + "." + System.currentTimeMillis() + ".quarantine");
            Files.move(filePath, dest, StandardCopyOption.REPLACE_EXISTING);
            alertSystem.critical("Guardian", filePath.getFileName().toString(),
                    "File quarantined to: " + dest);
        } catch (IOException e) {
            logger.warning("[Guardian] Failed to quarantine " + filePath + ": " + e.getMessage());
        }
    }

    private boolean hasMonitoredExtension(String filename) {
        return scanExtensions.stream().anyMatch(ext -> filename.toLowerCase().endsWith(ext));
    }
}
