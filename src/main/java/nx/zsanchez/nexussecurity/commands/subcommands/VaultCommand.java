package nx.zsanchez.nexussecurity.commands.subcommands;

import nx.zsanchez.nexussecurity.NexusSecurity;
import nx.zsanchez.nexussecurity.modules.vault.BackupScheduler;
import nx.zsanchez.nexussecurity.modules.vault.Vault;
import nx.zsanchez.nexussecurity.util.MessageFormatter;
import org.bukkit.ChatColor;
import org.bukkit.command.CommandSender;

/**
 * Handles /security vault subcommand: manual backup, listing and restore.
 */
public class VaultCommand {

    private final NexusSecurity plugin;

    public VaultCommand(NexusSecurity plugin) {
        this.plugin = plugin;
    }

    public void execute(CommandSender sender, String[] args) {
        Vault vault = plugin.getModuleManager().getModule("vault", Vault.class);
        if (vault == null) {
            sender.sendMessage(MessageFormatter.error("Módulo Vault no registrado."));
            return;
        }

        if (args.length < 2) {
            sender.sendMessage(MessageFormatter.header("NexusSecurity — Vault"));
            sender.sendMessage(MessageFormatter.keyValue("Estado", vault.getStatusSummary()));
            sender.sendMessage(ChatColor.GRAY + "Uso: /security vault [backup|list|restore <archivo>]");
            return;
        }

        String sub = args[1].toLowerCase();
        switch (sub) {
            case "backup" -> plugin.getThreadPoolManager().submit("ManualVaultBackup", () -> {
                if (!vault.isEnabled()) {
                    sender.sendMessage(MessageFormatter.error("El módulo Vault no está activo."));
                    return;
                }
                sender.sendMessage(MessageFormatter.info("Vault: Iniciando backup manual en segundo plano..."));
                vault.getBackupScheduler().performBackupNow();
                sender.sendMessage(MessageFormatter.success("Backup manual iniciado."));
            });
            case "list" -> plugin.getThreadPoolManager().submit("ListVaultBackups", () -> {
                if (!vault.isEnabled()) {
                    sender.sendMessage(MessageFormatter.error("El módulo Vault no está activo."));
                    return;
                }
                sender.sendMessage(MessageFormatter.header("NexusSecurity — Backups"));
                BackupScheduler scheduler = vault.getBackupScheduler();
                java.util.List<String> lines = scheduler.listBackups();
                if (lines.isEmpty()) {
                    sender.sendMessage(MessageFormatter.info("No hay backups aún. Usa /security vault backup."));
                } else {
                    lines.forEach(sender::sendMessage);
                }
            });
            case "restore" -> {
                if (args.length < 3) {
                    sender.sendMessage(MessageFormatter.error("Especifica el archivo: /security vault restore <archivo>"));
                    return;
                }
                if (!vault.isEnabled()) {
                    sender.sendMessage(MessageFormatter.error("El módulo Vault no está activo."));
                    return;
                }
                String file = args[2];
                plugin.getThreadPoolManager().submit("VaultRestore", () -> {
                    sender.sendMessage(MessageFormatter.critical("Restaurando backup '" + file + "'..."));
                    BackupScheduler.RestoreOutcome outcome = vault.getBackupScheduler().restoreBackup(file);
                    if (outcome.success()) {
                        sender.sendMessage(MessageFormatter.success("Restore completado: " + outcome.summary()));
                    } else {
                        sender.sendMessage(MessageFormatter.error("Restore fallido: " + outcome.summary()));
                    }
                });
            }
            default -> sender.sendMessage(MessageFormatter.error("Subcomando Vault desconocido: " + sub));
        }
    }
}
