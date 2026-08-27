package nx.zsanchez.nexussecurity.commands.subcommands;

import nx.zsanchez.nexussecurity.NexusSecurity;
import nx.zsanchez.nexussecurity.modules.hackdetector.HackDetector;
import nx.zsanchez.nexussecurity.util.MessageFormatter;
import org.bukkit.ChatColor;
import org.bukkit.command.CommandSender;

/**
 * Handles /security hackdetector subcommand.
 */
public class HackDetectorCommand {

    private final NexusSecurity plugin;

    public HackDetectorCommand(NexusSecurity plugin) {
        this.plugin = plugin;
    }

    public void execute(CommandSender sender, String[] args) {
        HackDetector hackDetector = plugin.getModuleManager().getModule("hackdetector", HackDetector.class);
        if (hackDetector == null) {
            sender.sendMessage(MessageFormatter.error("Módulo HackDetector no registrado."));
            return;
        }

        if (args.length < 2) {
            sender.sendMessage(MessageFormatter.header("NexusSecurity — HackDetector"));
            sender.sendMessage(MessageFormatter.keyValue("Estado", hackDetector.getStatusSummary()));
            sender.sendMessage(ChatColor.GRAY + "Uso: /security hackdetector [enable|disable]");
            return;
        }

        String sub = args[1].toLowerCase();
        switch (sub) {
            case "enable" -> {
                plugin.getModuleManager().enableModule("hackdetector");
                sender.sendMessage(MessageFormatter.success("Módulo HackDetector activado."));
            }
            case "disable" -> {
                plugin.getModuleManager().disableModule("hackdetector");
                sender.sendMessage(MessageFormatter.warning("Módulo HackDetector desactivado."));
            }
            default -> sender.sendMessage(MessageFormatter.error("Subcomando HackDetector desconocido: " + sub));
        }
    }
}
