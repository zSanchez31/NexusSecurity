package nx.zsanchez.nexussecurity.commands.subcommands;

import nx.zsanchez.nexussecurity.NexusSecurity;
import nx.zsanchez.nexussecurity.modules.shield.Shield;
import nx.zsanchez.nexussecurity.util.MessageFormatter;
import org.bukkit.ChatColor;
import org.bukkit.command.CommandSender;

/**
 * Handles /security shield subcommand.
 */
public class ShieldCommand {

    private final NexusSecurity plugin;

    public ShieldCommand(NexusSecurity plugin) {
        this.plugin = plugin;
    }

    public void execute(CommandSender sender, String[] args) {
        Shield shield = plugin.getModuleManager().getModule("shield", Shield.class);
        if (shield == null) {
            sender.sendMessage(MessageFormatter.error("Módulo Shield no registrado."));
            return;
        }

        if (args.length < 2) {
            sender.sendMessage(MessageFormatter.header("NexusSecurity — Shield"));
            sender.sendMessage(MessageFormatter.keyValue("Estado", shield.getStatusSummary()));
            sender.sendMessage(MessageFormatter.keyValue("AntiVPN", shield.getAntiVPN().isEnabled() ? "Activo" : "Inactivo"));
            sender.sendMessage(MessageFormatter.keyValue("GeoBlocker", shield.getGeoBlocker().isEnabled() ? "Activo" : "Inactivo"));
            sender.sendMessage(MessageFormatter.keyValue("RateLimiter", shield.getRateLimiter().isEnabled() ? "Activo" : "Inactivo"));
            sender.sendMessage(ChatColor.GRAY + "Uso: /security shield [enable|disable|unban <ip>]");
            return;
        }

        String sub = args[1].toLowerCase();
        switch (sub) {
            case "enable" -> {
                plugin.getModuleManager().enableModule("shield");
                sender.sendMessage(MessageFormatter.success("Módulo Shield activado."));
            }
            case "disable" -> {
                plugin.getModuleManager().disableModule("shield");
                sender.sendMessage(MessageFormatter.warning("Módulo Shield desactivado."));
            }
            case "unban" -> {
                if (args.length >= 3) {
                    String ip = args[2];
                    shield.getRateLimiter().unban(ip);
                    sender.sendMessage(MessageFormatter.success("IP " + ip + " removida de la lista de rate limit."));
                } else {
                    sender.sendMessage(MessageFormatter.error("Especifica una IP: /security shield unban <ip>"));
                }
            }
            default -> sender.sendMessage(MessageFormatter.error("Subcomando Shield desconocido: " + sub));
        }
    }
}
