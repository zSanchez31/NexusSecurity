package nx.zsanchez.nexussecurity.listeners;

import nx.zsanchez.nexussecurity.NexusSecurity;
import nx.zsanchez.nexussecurity.modules.hackdetector.HackDetector;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.entity.EntityDamageByEntityEvent;
import org.bukkit.event.player.PlayerMoveEvent;

/**
 * Listens to player movement and combat damage events for HackDetector analysis.
 */
public class PlayerMoveListener implements Listener {

    private final NexusSecurity plugin;

    public PlayerMoveListener(NexusSecurity plugin) {
        this.plugin = plugin;
    }

    @EventHandler(priority = EventPriority.MONITOR, ignoreCancelled = true)
    public void onMove(PlayerMoveEvent event) {
        HackDetector hackDetector = plugin.getModuleManager().getModule("hackdetector", HackDetector.class);
        if (hackDetector != null && hackDetector.isEnabled()) {
            hackDetector.onPlayerMove(event.getPlayer(), event.getFrom(), event.getTo());
        }
    }

    @EventHandler(priority = EventPriority.MONITOR, ignoreCancelled = true)
    public void onAttack(EntityDamageByEntityEvent event) {
        if (event.getDamager() instanceof Player attacker) {
            HackDetector hackDetector = plugin.getModuleManager().getModule("hackdetector", HackDetector.class);
            if (hackDetector != null && hackDetector.isEnabled()) {
                hackDetector.onPlayerAttack(attacker, event.getEntity());
            }
        }
    }
}
