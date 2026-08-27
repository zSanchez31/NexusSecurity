package nx.zsanchez.nexussecurity.commands.subcommands;

import nx.zsanchez.nexussecurity.NexusSecurity;
import nx.zsanchez.nexussecurity.modules.autopilot.Autopilot;
import nx.zsanchez.nexussecurity.util.MessageFormatter;
import org.bukkit.ChatColor;
import org.bukkit.command.CommandSender;

/**
 * Handles /security autopilot subcommand.
 */
public class AutopilotCommand {

    private final NexusSecurity plugin;

    public AutopilotCommand(NexusSecurity plugin) {
        this.plugin = plugin;
    }

    public void execute(CommandSender sender, String[] args) {
        Autopilot autopilot = plugin.getModuleManager().getModule("autopilot", Autopilot.class);
        if (autopilot == null) {
            sender.sendMessage(MessageFormatter.error("Módulo Autopilot no registrado."));
            return;
        }

        if (args.length < 2) {
            sender.sendMessage(MessageFormatter.header("NexusSecurity — Autopilot"));
            sender.sendMessage(MessageFormatter.keyValue("Estado", autopilot.getStatusSummary()));
            sender.sendMessage(ChatColor.GRAY + "Uso: /security autopilot [enable|disable|emergency]");
            return;
        }

        String sub = args[1].toLowerCase();
        switch (sub) {
            case "enable" -> {
                plugin.getModuleManager().enableModule("autopilot");
                sender.sendMessage(MessageFormatter.success("Módulo Autopilot activado."));
            }
            case "disable" -> {
                plugin.getModuleManager().disableModule("autopilot");
                sender.sendMessage(MessageFormatter.warning("Módulo Autopilot desactivado."));
            }
            case "emergency" -> {
                boolean active = autopilot.getEmergencyMode().isActive();
                if (active) {
                    autopilot.getEmergencyMode().deactivate();
                    sender.sendMessage(MessageFormatter.success("Modo de Emergencia DESACTIVADO."));
                } else {
                    autopilot.getEmergencyMode().activate();
                    sender.sendMessage(MessageFormatter.critical("Modo de Emergencia ACTIVADO manualmente."));
                }
            }
            default -> sender.sendMessage(MessageFormatter.error("Subcomando Autopilot desconocido: " + sub));
        }
    }
}
