package nx.zsanchez.nexussecurity.commands.subcommands;

import nx.zsanchez.nexussecurity.NexusSecurity;
import nx.zsanchez.nexussecurity.modules.compliance.Compliance;
import nx.zsanchez.nexussecurity.modules.compliance.ComplianceChecklist;
import nx.zsanchez.nexussecurity.util.MessageFormatter;
import org.bukkit.ChatColor;
import org.bukkit.command.CommandSender;

import java.util.List;

/**
 * Handles /security compliance subcommand: log search, report generation and self-assessment checklist.
 */
public class ComplianceCommand {

    private final NexusSecurity plugin;

    public ComplianceCommand(NexusSecurity plugin) {
        this.plugin = plugin;
    }

    public void execute(CommandSender sender, String[] args) {
        Compliance compliance = plugin.getModuleManager().getModule("compliance", Compliance.class);
        if (compliance == null) {
            sender.sendMessage(MessageFormatter.error("Módulo Compliance no registrado."));
            return;
        }

        if (args.length < 2) {
            sender.sendMessage(MessageFormatter.header("NexusSecurity — Compliance"));
            sender.sendMessage(MessageFormatter.keyValue("Estado", compliance.getStatusSummary()));
            sender.sendMessage(ChatColor.GRAY + "Uso: /security compliance [search <consulta> [límite]|report|check]");
            return;
        }

        String sub = args[1].toLowerCase();
        switch (sub) {
            case "search" -> {
                if (args.length < 3) {
                    sender.sendMessage(MessageFormatter.error("Especifica una consulta: /security compliance search <texto> [límite]"));
                    return;
                }
                if (!compliance.isEnabled()) {
                    sender.sendMessage(MessageFormatter.error("El módulo Compliance no está activo."));
                    return;
                }
                String query = args[2];
                int limit = args.length >= 4 ? parseInt(args[3]) : 25;
                plugin.getThreadPoolManager().submit("ComplianceSearch", () -> {
                    List<String> results = compliance.getReportGenerator().searchAuditLogs(query, limit);
                    sender.sendMessage(MessageFormatter.header("Búsqueda de auditoría: '" + query + "'"));
                    if (results.isEmpty()) {
                        sender.sendMessage(MessageFormatter.info("Sin resultados para la consulta."));
                    } else {
                        results.forEach(line -> sender.sendMessage(MessageFormatter.colorize(line)));
                    }
                });
            }
            case "report" -> plugin.getThreadPoolManager().submit("ComplianceReport", () -> {
                if (!compliance.isEnabled()) {
                    sender.sendMessage(MessageFormatter.error("El módulo Compliance no está activo."));
                    return;
                }
                sender.sendMessage(MessageFormatter.info("Generando informe de auditoría..."));
                java.io.File report = compliance.getReportGenerator().generateScheduledReport();
                if (report != null) {
                    sender.sendMessage(MessageFormatter.success("Informe generado: " + report.getAbsolutePath()));
                } else {
                    sender.sendMessage(MessageFormatter.error("No se pudo generar el informe."));
                }
            });
            case "check" -> plugin.getThreadPoolManager().submit("ComplianceChecklist", () -> {
                if (!compliance.isEnabled()) {
                    sender.sendMessage(MessageFormatter.error("El módulo Compliance no está activo."));
                    return;
                }
                List<ComplianceChecklist.CheckItem> items = compliance.getComplianceChecklist().runChecks();
                long passed = items.stream().filter(ComplianceChecklist.CheckItem::passed).count();
                sender.sendMessage(MessageFormatter.header("Checklist de cumplimiento (" + passed + "/" + items.size() + ")"));
                for (ComplianceChecklist.CheckItem item : items) {
                    String status = item.passed() ? ChatColor.GREEN + "PASS" : ChatColor.RED + "FAIL";
                    sender.sendMessage(ChatColor.GRAY + "  " + status + ChatColor.WHITE + " " + item.id()
                            + ChatColor.GRAY + " · " + ChatColor.AQUA + item.category()
                            + ChatColor.DARK_GRAY + " → " + ChatColor.WHITE + item.description()
                            + ChatColor.GRAY + " (" + item.detail() + ")");
                }
            });
            default -> sender.sendMessage(MessageFormatter.error("Subcomando Compliance desconocido: " + sub));
        }
    }

    private int parseInt(String value) {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            return 25;
        }
    }
}
