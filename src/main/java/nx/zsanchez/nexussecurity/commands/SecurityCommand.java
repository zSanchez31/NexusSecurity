package nx.zsanchez.nexussecurity.commands;

import nx.zsanchez.nexussecurity.NexusSecurity;
import nx.zsanchez.nexussecurity.commands.subcommands.*;
import nx.zsanchez.nexussecurity.util.MessageFormatter;
import org.bukkit.ChatColor;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.command.TabCompleter;

import java.util.ArrayList;
import java.util.List;

/**
 * Main command executor and tab completer for /security.
 */
public class SecurityCommand implements CommandExecutor, TabCompleter {

    private final NexusSecurity plugin;
    private final StatusCommand statusCommand;
    private final ShieldCommand shieldCommand;
    private final HackDetectorCommand hackDetectorCommand;
    private final AutopilotCommand autopilotCommand;
    private final VaultCommand vaultCommand;
    private final ComplianceCommand complianceCommand;
    private final VulnerabilityCommand vulnerabilityCommand;
    private final MemoryCommand memoryCommand;
    private final PanelCommand panelCommand;

    public SecurityCommand(NexusSecurity plugin) {
        this.plugin = plugin;
        this.statusCommand = new StatusCommand(plugin);
        this.shieldCommand = new ShieldCommand(plugin);
        this.hackDetectorCommand = new HackDetectorCommand(plugin);
        this.autopilotCommand = new AutopilotCommand(plugin);
        this.vaultCommand = new VaultCommand(plugin);
        this.complianceCommand = new ComplianceCommand(plugin);
        this.vulnerabilityCommand = new VulnerabilityCommand(plugin);
        this.memoryCommand = new MemoryCommand(plugin);
        this.panelCommand = new PanelCommand(plugin);
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (!sender.hasPermission("nexussecurity.admin")) {
            sender.sendMessage(MessageFormatter.error("No tienes permiso para ejecutar comandos de NexusSecurity."));
            return true;
        }

        if (args.length == 0) {
            sendHelp(sender);
            return true;
        }

        String subcommand = args[0].toLowerCase();
        switch (subcommand) {
            case "status" -> statusCommand.execute(sender, args);
            case "shield" -> shieldCommand.execute(sender, args);
            case "hackdetector" -> hackDetectorCommand.execute(sender, args);
            case "autopilot" -> autopilotCommand.execute(sender, args);
            case "vault" -> vaultCommand.execute(sender, args);
            case "compliance" -> complianceCommand.execute(sender, args);
            case "vuln", "vulnerability" -> vulnerabilityCommand.execute(sender, args);
            case "memory", "mem" -> memoryCommand.execute(sender, args);
            case "panel", "web" -> panelCommand.execute(sender, args);
            case "backup" -> {
                plugin.getThreadPoolManager().submit("ManualBackup", () -> {
                    var vault = plugin.getModuleManager().getModule("vault", nx.zsanchez.nexussecurity.modules.vault.Vault.class);
                    if (vault != null && vault.isEnabled()) {
                        vault.getBackupScheduler().performBackupNow();
                        sender.sendMessage(MessageFormatter.success("Backup manual iniciado en segundo plano."));
                    } else {
                        sender.sendMessage(MessageFormatter.error("El módulo Vault no está activo."));
                    }
                });
            }
            case "scan" -> {
                plugin.getThreadPoolManager().submit("ManualScan", () -> {
                    var guardian = plugin.getModuleManager().getModule("guardian", nx.zsanchez.nexussecurity.modules.guardian.Guardian.class);
                    if (guardian != null && guardian.isEnabled()) {
                        sender.sendMessage(MessageFormatter.info("Guardia: Iniciando escaneo de archivos e integridad..."));
                        guardian.runScan();
                        sender.sendMessage(MessageFormatter.success("Escaneo manual completado."));
                    } else {
                        sender.sendMessage(MessageFormatter.error("El módulo Guardian no está activo."));
                    }
                });
            }
            case "reload", "config" -> {
                plugin.reloadConfig();
                plugin.getAlertSystem().loadConfig();
                plugin.getPerformanceMonitor().loadThresholds();
                plugin.getMemoryWatchdog().loadConfig();
                plugin.getWebPanel().reload();
                sender.sendMessage(MessageFormatter.success("Configuración de NexusSecurity recargada correctamente."));
            }
            case "logs" -> plugin.getThreadPoolManager().submit("ExportAuditLogs", () -> {
                var compliance = plugin.getModuleManager().getModule("compliance", nx.zsanchez.nexussecurity.modules.compliance.Compliance.class);
                if (compliance == null || !compliance.isEnabled()) {
                    sender.sendMessage(MessageFormatter.error("El módulo Compliance no está activo."));
                    return;
                }
                java.io.File report = compliance.getReportGenerator().exportAuditLogCsv();
                if (report != null) {
                    sender.sendMessage(MessageFormatter.success("Informe de auditoría exportado: " + report.getAbsolutePath()));
                } else {
                    sender.sendMessage(MessageFormatter.error("No se pudo exportar el informe de auditoría."));
                }
            });
            default -> sendHelp(sender);
        }

        return true;
    }

    private void sendHelp(CommandSender sender) {
        sender.sendMessage(MessageFormatter.header("NexusSecurity — Ayuda"));
        sender.sendMessage(ChatColor.AQUA + "/security status " + ChatColor.GRAY + "— Estado general y telemetría");
        sender.sendMessage(ChatColor.AQUA + "/security shield " + ChatColor.GRAY + "— Gestionar módulo Shield / AntiVPN");
        sender.sendMessage(ChatColor.AQUA + "/security hackdetector " + ChatColor.GRAY + "— Gestionar HackDetector");
        sender.sendMessage(ChatColor.AQUA + "/security autopilot " + ChatColor.GRAY + "— Gestionar Autopilot y Emergencia");
        sender.sendMessage(ChatColor.AQUA + "/security vault " + ChatColor.GRAY + "— Backups, lista y restauración");
        sender.sendMessage(ChatColor.AQUA + "/security compliance " + ChatColor.GRAY + "— Búsqueda de logs, informes y checklist");
        sender.sendMessage(ChatColor.AQUA + "/security vuln " + ChatColor.GRAY + "— Escaneo de CVEs y hallazgos");
        sender.sendMessage(ChatColor.AQUA + "/security memory " + ChatColor.GRAY + "— Uso de memoria JVM y recursos");
        sender.sendMessage(ChatColor.AQUA + "/security panel " + ChatColor.GRAY + "— URL y estado del panel web");
        sender.sendMessage(ChatColor.AQUA + "/security backup " + ChatColor.GRAY + "— Ejecutar backup manual");
        sender.sendMessage(ChatColor.AQUA + "/security scan " + ChatColor.GRAY + "— Ejecutar escaneo de archivos");
        sender.sendMessage(ChatColor.AQUA + "/security logs " + ChatColor.GRAY + "— Exportar informe de auditoría");
        sender.sendMessage(ChatColor.AQUA + "/security reload " + ChatColor.GRAY + "— Recargar configuración (alias: config)");
    }

    @Override
    public List<String> onTabComplete(CommandSender sender, Command command, String alias, String[] args) {
        List<String> completions = new ArrayList<>();
        if (!sender.hasPermission("nexussecurity.admin")) return completions;

        if (args.length == 1) {
            completions.addAll(List.of("status", "shield", "hackdetector", "autopilot", "vault", "compliance", "vuln",
                    "memory", "panel", "backup", "scan", "logs", "config", "reload"));
        } else if (args.length == 2) {
            String sub = args[0].toLowerCase();
            switch (sub) {
                case "shield" -> completions.addAll(List.of("enable", "disable", "unban"));
                case "hackdetector" -> completions.addAll(List.of("enable", "disable"));
                case "autopilot" -> completions.addAll(List.of("enable", "disable", "emergency"));
                case "vault" -> completions.addAll(List.of("backup", "list", "restore"));
                case "compliance" -> completions.addAll(List.of("search", "report", "check"));
                case "vuln", "vulnerability" -> completions.addAll(List.of("scan", "findings"));
            }
        }
        return completions.stream()
                .filter(s -> s.startsWith(args[args.length - 1].toLowerCase()))
                .toList();
    }
}
