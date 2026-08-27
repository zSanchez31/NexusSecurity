package nx.zsanchez.nexussecurity.commands.subcommands;

import nx.zsanchez.nexussecurity.NexusSecurity;
import nx.zsanchez.nexussecurity.util.MessageFormatter;
import nx.zsanchez.nexussecurity.web.WebPanel;
import org.bukkit.ChatColor;
import org.bukkit.command.CommandSender;

/**
 * Handles /security panel subcommand. Shows the web panel URL, running state and password guidance.
 */
public class PanelCommand {

    private final NexusSecurity plugin;

    public PanelCommand(NexusSecurity plugin) {
        this.plugin = plugin;
    }

    public void execute(CommandSender sender, String[] args) {
        var panel = plugin.getWebPanel();
        sender.sendMessage(MessageFormatter.header("NexusSecurity — Panel Web"));

        if (!panel.isRunning()) {
            sender.sendMessage(MessageFormatter.keyValue("Estado",
                    ChatColor.RED + "● DETENIDO (activa web-panel.enabled en config.yml)"));
            sender.sendMessage(MessageFormatter.keyValue("Puerto config",
                    String.valueOf(plugin.getConfig().getInt("web-panel.port", 25580))));
            return;
        }

        sender.sendMessage(MessageFormatter.keyValue("Estado", ChatColor.GREEN + "● ACTIVO"));
        sender.sendMessage(MessageFormatter.keyValue("URL", ChatColor.AQUA + panel.getPanelUrl()));
        sender.sendMessage(MessageFormatter.keyValue("Puerto", String.valueOf(plugin.getConfig().getInt("web-panel.port", 25580))));
        sender.sendMessage(MessageFormatter.keyValue("Autenticación",
                plugin.getConfig().getBoolean("web-panel.require-password", true)
                        ? ChatColor.YELLOW + "Contraseña requerida" : ChatColor.GRAY + "Sin contraseña"));

        if (panel.isDefaultPassword() && plugin.getConfig().getBoolean("web-panel.require-password", true)) {
            sender.sendMessage(MessageFormatter.keyValue("Contraseña",
                    ChatColor.RED + WebPanel.DEFAULT_PASSWORD + " (por defecto — cámbiala en config.yml)"));
            sender.sendMessage(ChatColor.RED + "⚠ Por seguridad, cambia web-panel.password en config.yml. "
                    + "Dejarla por defecto expone el panel.");
        }
    }
}
