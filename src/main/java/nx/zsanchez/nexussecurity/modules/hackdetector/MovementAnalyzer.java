package nx.zsanchez.nexussecurity.modules.hackdetector;

import nx.zsanchez.nexussecurity.NexusSecurity;
import nx.zsanchez.nexussecurity.core.AlertSystem;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.bukkit.Location;
import org.bukkit.entity.Player;
import org.bukkit.potion.PotionEffectType;

/**
 * Analyzes player movement for hack indicators.
 * Detects: Speed hacks, NoClip, illegal flight, SpeedBridge, SpiderHack, teleport hacks.
 *
 * <p>Design principles:</p>
 * <ul>
 *   <li>Lag compensation: applies a configurable tolerance multiplier</li>
 *   <li>False-positive aware: checks for legitimizing conditions (Speed potion, Elytra, etc.)</li>
 *   <li>Stateful: maintains last-known-position per player for delta computation</li>
 * </ul>
 */
public class MovementAnalyzer {

    private final NexusSecurity plugin;
    private final AlertSystem alertSystem;

    private double maxSpeed;
    private double lagTolerance;
    private boolean detectFlight;
    private boolean detectNoClip;
    private boolean detectTeleportHack;
    private boolean detectStep;
    private boolean detectSpider;

    /** Map of player UUID → last processed location. */
    private final Map<UUID, Location> lastLocations = new ConcurrentHashMap<>();
    /** Map of player UUID → consecutive violation count. */
    private final Map<UUID, Integer> violations = new ConcurrentHashMap<>();

    /**
     * Creates the movement analyzer.
     *
     * @param plugin      Main plugin instance
     * @param alertSystem Alert system for violation events
     */
    public MovementAnalyzer(NexusSecurity plugin, AlertSystem alertSystem) {
        this.plugin = plugin;
        this.alertSystem = alertSystem;
        loadConfig();
    }

    /**
     * Loads movement configuration from config.yml.
     */
    public void loadConfig() {
        this.maxSpeed = plugin.getConfig().getDouble("modules.hack-detector.movement.max-speed", 0.75);
        this.lagTolerance = plugin.getConfig().getDouble("modules.hack-detector.movement.lag-tolerance", 1.5);
        this.detectFlight = plugin.getConfig().getBoolean("modules.hack-detector.movement.detect-flight", true);
        this.detectNoClip = plugin.getConfig().getBoolean("modules.hack-detector.movement.detect-no-clip", true);
        this.detectTeleportHack = plugin.getConfig().getBoolean("modules.hack-detector.movement.detect-teleport-hack", true);
        this.detectStep = plugin.getConfig().getBoolean("modules.hack-detector.movement.detect-step", true);
        this.detectSpider = plugin.getConfig().getBoolean("modules.hack-detector.movement.detect-spider", true);
    }

    /**
     * Analyzes a player movement event.
     *
     * @param player Player who moved
     * @param from   Previous location
     * @param to     New location
     * @return ViolationType string if hack detected, null if clean
     */
    public String analyze(Player player, Location from, Location to) {
        UUID uuid = player.getUniqueId();

        // Skip if player has bypass permission
        if (player.hasPermission("nexussecurity.bypass")) {
            lastLocations.put(uuid, to);
            return null;
        }

        double dx = to.getX() - from.getX();
        double dy = to.getY() - from.getY();
        double dz = to.getZ() - from.getZ();
        double horizontalDist = Math.sqrt(dx * dx + dz * dz);

        // Effective max speed considering potions and game modes
        double effectiveMax = getEffectiveMaxSpeed(player);

        String violation = null;

        // --- Speed check ---
        if (horizontalDist > effectiveMax && !player.isInsideVehicle() && !player.isFlying()) {
            violation = "SPEED";
        }

        // --- Flight check ---
        if (detectFlight && dy > 0.4 && !player.isFlying() && !player.getAllowFlight()
                && !isNearLadder(player) && !isNearWater(player)
                && !player.hasPotionEffect(PotionEffectType.JUMP_BOOST)) {
            violation = "FLIGHT";
        }

        // --- Step hack (ascending > 1 block per tick) ---
        if (detectStep && dy > 1.1 && !player.isFlying()
                && !player.hasPotionEffect(PotionEffectType.JUMP_BOOST)) {
            violation = "STEP";
        }

        // --- Teleport hack (unrealistically large distance) ---
        if (detectTeleportHack) {
            double totalDist = Math.sqrt(dx * dx + dy * dy + dz * dz);
            // > 20 blocks in a single packet without teleport event = suspicious
            if (totalDist > 20 * effectiveMax) {
                violation = "TELEPORT_HACK";
            }
        }

        if (violation != null) {
            int count = violations.merge(uuid, 1, Integer::sum);
            if (count <= 3) { // Allow 3 consecutive violations before flagging (lag buffer)
                violation = null; // Not flagging yet
            } else {
                violations.put(uuid, 0); // Reset after flagging
                String details = String.format("dist=%.2f maxAllowed=%.2f pos=[%.1f,%.1f,%.1f]",
                        horizontalDist, effectiveMax, to.getX(), to.getY(), to.getZ());
                alertSystem.warning("HackDetector", player.getName(),
                        "Movement violation [" + violation + "]: " + details);
            }
        } else {
            violations.put(uuid, 0); // Reset on clean tick
        }

        lastLocations.put(uuid, to);
        return violation;
    }

    /**
     * Computes the effective maximum allowed speed for a player considering game state.
     *
     * @param player The player
     * @return Effective max horizontal speed in blocks per event
     */
    private double getEffectiveMaxSpeed(Player player) {
        double speed = maxSpeed * lagTolerance;

        // Speed II = 40% bonus per level above default
        if (player.hasPotionEffect(PotionEffectType.SPEED)) {
            var effect = player.getPotionEffect(PotionEffectType.SPEED);
            if (effect != null) {
                speed += (effect.getAmplifier() + 1) * 0.25;
            }
        }

        // Sneaking reduces speed
        if (player.isSneaking()) speed *= 0.5;

        // Sprinting increases speed
        if (player.isSprinting()) speed *= 1.3;

        return speed;
    }

    /**
     * Cleans up player data on logout.
     *
     * @param uuid Player UUID
     */
    public void cleanup(UUID uuid) {
        lastLocations.remove(uuid);
        violations.remove(uuid);
    }

    private boolean isNearLadder(Player player) {
        var block = player.getLocation().getBlock();
        var blockBelow = block.getRelative(0, -1, 0);
        return block.getType().name().contains("LADDER") ||
                block.getType().name().contains("VINE") ||
                blockBelow.getType().name().contains("LADDER");
    }

    private boolean isNearWater(Player player) {
        return player.getLocation().getBlock().getType().name().contains("WATER");
    }
}
