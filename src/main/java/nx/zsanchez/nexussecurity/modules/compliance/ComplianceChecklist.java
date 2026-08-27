package nx.zsanchez.nexussecurity.modules.compliance;

import nx.zsanchez.nexussecurity.NexusSecurity;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

/**
 * Self-assessment checklist against common server hardening recommendations
 * (CIS-style baseline). Each check returns PASS / FAIL / INFO so admins can
 * see at a glance how hardened their server configuration is.
 */
public class ComplianceChecklist {

    /** A single checklist item result. */
    public record CheckItem(String id, String category, String description, boolean passed, String detail) {}

    private final NexusSecurity plugin;

    public ComplianceChecklist(NexusSecurity plugin) {
        this.plugin = plugin;
    }

    /**
     * Runs all self-assessment checks against the live server configuration.
     *
     * @return List of check results
     */
    public List<CheckItem> runChecks() {
        List<CheckItem> items = new ArrayList<>();
        Path serverRoot = plugin.getDataFolder().getParentFile().toPath();

        Properties props = readProperties(serverRoot.resolve("server.properties"));
        if (props != null) {
            items.add(boolCheck("SRV-001", "Servidor", "Online-mode habilitado (anti-pirate/identity spoofing)",
                    Boolean.parseBoolean(props.getProperty("online-mode", "false")),
                    "online-mode=" + props.getProperty("online-mode")));
            items.add(boolCheck("SRV-002", "Servidor", "Comandos de bloqueo de estructura deshabilitados (command-blocks)",
                    !Boolean.parseBoolean(props.getProperty("enable-command-block", "false")),
                    "enable-command-block=" + props.getProperty("enable-command-block")));
            items.add(boolCheck("SRV-003", "Servidor", "Whitelist activada",
                    Boolean.parseBoolean(props.getProperty("white-list", "false")),
                    "white-list=" + props.getProperty("white-list")));
        } else {
            items.add(new CheckItem("SRV-000", "Servidor", "Verificar server.properties", false,
                    "No se pudo leer server.properties"));
        }

        boolean offlineOnly = plugin.getConfig().getBoolean("api.dev-mode", false)
                || "TU_CLAVE_API_AQUI".equals(plugin.getConfig().getString("api.key", ""));
        items.add(boolCheck("NEX-001", "NexusSecurity", "Clave API de suscripción configurada",
                !offlineOnly,
                "api.key: " + (offlineOnly ? "(vacía/por defecto)" : "configurada")));
        items.add(boolCheck("NEX-002", "NexusSecurity", "Contraseña de cifrado de Vault personalizada",
                !"CHANGE_THIS_STRONG_PASSWORD_NOW".equals(plugin.getConfig().getString("modules.vault.encryption-password", "")),
                "Se recomienda una contraseña fuerte y única"));
        items.add(boolCheck("NEX-003", "NexusSecurity", "Modo debug desactivado en producción",
                !plugin.getConfig().getBoolean("debug.enabled", false),
                "debug.enabled=" + plugin.getConfig().getBoolean("debug.enabled", false)));

        // Server version / TPS health
        double tps = plugin.getPerformanceMonitor().getCurrentTps();
        items.add(boolCheck("PERF-001", "Rendimiento", "TPS estable (≥ 17)",
                tps >= 17.0,
                String.format("TPS actual: %.1f", tps)));
        items.add(boolCheck("PERF-002", "Rendimiento", "CPU del proceso dentro de límites (≤ 85%)",
                plugin.getPerformanceMonitor().getCpuUsagePercent() <= 85.0,
                String.format("CPU: %.1f%%", plugin.getPerformanceMonitor().getCpuUsagePercent())));

        return items;
    }

    private CheckItem boolCheck(String id, String category, String description, boolean passed, String detail) {
        return new CheckItem(id, category, description, passed, detail);
    }

    private Properties readProperties(Path file) {
        if (file == null || !Files.exists(file)) return null;
        Properties props = new Properties();
        try (var reader = Files.newBufferedReader(file)) {
            props.load(reader);
            return props;
        } catch (IOException e) {
            return null;
        }
    }
}
