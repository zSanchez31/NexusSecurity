package nx.zsanchez.nexussecurity.modules.compliance;

import nx.zsanchez.nexussecurity.NexusSecurity;
import nx.zsanchez.nexussecurity.core.DatabaseManager;

import java.io.File;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.logging.Logger;

/**
 * Generates technical and executive security compliance reports in CSV, JSON, or TXT format.
 */
public class ReportGenerator {

    private final NexusSecurity plugin;
    private final Logger logger;
    private final DatabaseManager databaseManager;

    public ReportGenerator(NexusSecurity plugin, DatabaseManager databaseManager) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
        this.databaseManager = databaseManager;
    }

    /**
     * Exports audit log entries to a CSV file in nexus-exports directory.
     * Async operation.
     */
    public File exportAuditLogCsv() {
        File exportDir = new File(plugin.getDataFolder(), "nexus-exports");
        if (!exportDir.exists()) exportDir.mkdirs();

        String timestamp = new SimpleDateFormat("yyyy-MM-dd_HH-mm-ss").format(new Date());
        File csvFile = new File(exportDir, "audit_report_" + timestamp + ".csv");

        try (Connection conn = databaseManager.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery("SELECT * FROM audit_log ORDER BY id DESC LIMIT 5000");
             PrintWriter pw = new PrintWriter(csvFile)) {

            pw.println("ID,Timestamp,Actor,ActorType,Action,Target,Result,IPAddress");

            while (rs.next()) {
                pw.printf("%d,%d,\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"%n",
                        rs.getInt("id"),
                        rs.getLong("timestamp"),
                        rs.getString("actor"),
                        rs.getString("actor_type"),
                        rs.getString("action"),
                        rs.getString("target"),
                        rs.getString("result"),
                        rs.getString("ip_address")
                );
            }
            logger.info("[ReportGenerator] Exported audit log CSV report: " + csvFile.getName());
            return csvFile;
        } catch (Exception e) {
            logger.severe("[ReportGenerator] Failed to export audit log report: " + e.getMessage());
            return null;
        }
    }

    /**
     * Advanced log search: filters the audit trail by actor, action, target, result, or IP.
     *
     * @param query Search term (SQL LIKE, case-insensitive)
     * @param limit Maximum number of rows to return
     * @return Formatted lines for the command output
     */
    public List<String> searchAuditLogs(String query, int limit) {
        List<String> lines = new ArrayList<>();
        String like = "%" + query.toLowerCase() + "%";
        String sql = "SELECT id, timestamp, actor, actor_type, action, target, result, ip_address " +
                "FROM audit_log WHERE LOWER(actor) LIKE ? OR LOWER(action) LIKE ? OR LOWER(target) LIKE ? " +
                "OR LOWER(result) LIKE ? OR LOWER(ip_address) LIKE ? ORDER BY id DESC LIMIT ?";

        try (Connection conn = databaseManager.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            for (int i = 1; i <= 4; i++) ps.setString(i, like);
            ps.setString(5, like);
            ps.setInt(6, Math.max(1, Math.min(limit, 200)));

            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    String stamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss")
                            .format(new Date(rs.getLong("timestamp")));
                    lines.add(String.format("  &7[%s] &f%s &7(%s) &f→ %s &7| %s &7| %s &7| %s",
                            stamp,
                            rs.getString("actor"),
                            rs.getString("actor_type"),
                            rs.getString("action"),
                            rs.getString("target") != null ? rs.getString("target") : "-",
                            rs.getString("result"),
                            rs.getString("ip_address") != null ? rs.getString("ip_address") : "-"));
                }
            }
            logger.info("[ReportGenerator] Search '" + query + "' returned " + lines.size() + " entries.");
        } catch (Exception e) {
            logger.severe("[ReportGenerator] Log search failed: " + e.getMessage());
        }
        return lines;
    }

    /**
     * Runs the configured automatic report generation (auto-export section of config).
     * Supports csv and json formats. Async.
     *
     * @return The generated file, or null on failure
     */
    public File generateScheduledReport() {
        String format = plugin.getConfig().getString("modules.compliance.auto-export.format", "json");
        if (format.equalsIgnoreCase("csv")) {
            return exportAuditLogCsv();
        }
        return exportAuditLogJson();
    }

    /**
     * Exports audit log entries to a JSON file in the configured export directory.
     *
     * @return The generated file, or null on failure
     */
    public File exportAuditLogJson() {
        File exportDir = new File(plugin.getDataFolder(),
                plugin.getConfig().getString("modules.compliance.auto-export.export-dir", "nexus-exports"));
        if (!exportDir.exists()) exportDir.mkdirs();

        String timestamp = new SimpleDateFormat("yyyy-MM-dd_HH-mm-ss").format(new Date());
        File jsonFile = new File(exportDir, "audit_report_" + timestamp + ".json");

        StringBuilder sb = new StringBuilder("[\n");
        boolean first = true;
        try (Connection conn = databaseManager.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery("SELECT * FROM audit_log ORDER BY id DESC LIMIT 5000")) {

            while (rs.next()) {
                if (!first) sb.append(",\n");
                first = false;
                sb.append("  {\"id\": ").append(rs.getInt("id"))
                        .append(", \"timestamp\": ").append(rs.getLong("timestamp"))
                        .append(", \"actor\": ").append(quote(rs.getString("actor")))
                        .append(", \"actor_type\": ").append(quote(rs.getString("actor_type")))
                        .append(", \"action\": ").append(quote(rs.getString("action")))
                        .append(", \"target\": ").append(quote(rs.getString("target")))
                        .append(", \"result\": ").append(quote(rs.getString("result")))
                        .append(", \"ip_address\": ").append(quote(rs.getString("ip_address")))
                        .append("}");
            }
            sb.append("\n]\n");
            try (PrintWriter pw = new PrintWriter(jsonFile)) {
                pw.print(sb);
            }
            logger.info("[ReportGenerator] Exported audit log JSON report: " + jsonFile.getName());
            return jsonFile;
        } catch (Exception e) {
            logger.severe("[ReportGenerator] Failed to export JSON report: " + e.getMessage());
            return null;
        }
    }

    private String quote(String value) {
        if (value == null) return "null";
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }
}
