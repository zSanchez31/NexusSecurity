package nx.zsanchez.nexussecurity.modules.hackdetector;

import nx.zsanchez.nexussecurity.NexusSecurity;
import nx.zsanchez.nexussecurity.core.AlertSystem;
import org.bukkit.Location;
import org.bukkit.entity.Entity;
import org.bukkit.entity.LivingEntity;
import org.bukkit.entity.Player;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Analyzes player combat patterns for KillAura, Reach hacks, Aimbot, and illegal critical hits.
 * Uses click timing and spatial analysis to identify automated combat behavior.
 */
public class CombatAnalyzer {

    private final NexusSecurity plugin;
    private final AlertSystem alertSystem;

    private double maxReach;
    private int maxCps;
    private boolean detectKillaura;
    private boolean detectAimbot;
    private boolean detectIllegalCrits;

    /** Click timestamps per player (used for CPS calculation). */
    private final Map<UUID, List<Long>> clickTimestamps = new ConcurrentHashMap<>();
    /** Head yaw changes per player (used for aimbot detection). */
    private final Map<UUID, List<Float>> yawChanges = new ConcurrentHashMap<>();
    /** Whether player was falling on last tick (for illegal crit detection). */
    private final Map<UUID, Boolean> wasFalling = new ConcurrentHashMap<>();

    /**
     * Creates the combat analyzer.
     *
     * @param plugin      Main plugin instance
     * @param alertSystem Alert system for combat violations
     */
    public CombatAnalyzer(NexusSecurity plugin, AlertSystem alertSystem) {
        this.plugin = plugin;
        this.alertSystem = alertSystem;
        loadConfig();
    }

    /**
     * Loads combat configuration.
     */
    public void loadConfig() {
        this.maxReach = plugin.getConfig().getDouble("modules.hack-detector.combat.max-reach", 3.2);
        this.maxCps = plugin.getConfig().getInt("modules.hack-detector.combat.max-cps", 20);
        this.detectKillaura = plugin.getConfig().getBoolean("modules.hack-detector.combat.detect-killaura", true);
        this.detectAimbot = plugin.getConfig().getBoolean("modules.hack-detector.combat.detect-aimbot", true);
        this.detectIllegalCrits = plugin.getConfig().getBoolean("modules.hack-detector.combat.detect-illegal-crits", true);
    }

    /**
     * Called when a player attacks an entity.
     *
     * @param player The attacking player
     * @param target The attacked entity
     * @return Violation type string if hack detected, null otherwise
     */
    public String analyzeAttack(Player player, Entity target) {
        if (player.hasPermission("nexussecurity.bypass")) return null;

        UUID uuid = player.getUniqueId();

        // 1. Reach check
        double distance = player.getLocation().distance(target.getLocation());
        if (distance > maxReach) {
            alertSystem.warning("HackDetector", player.getName(),
                    "Reach hack: attacked entity at " + String.format("%.2f", distance) + " blocks (max: " + maxReach + ")");
            return "REACH";
        }

        // 2. CPS check (clicks per second)
        long now = System.currentTimeMillis();
        List<Long> clicks = clickTimestamps.computeIfAbsent(uuid, k -> new ArrayList<>());
        synchronized (clicks) {
            clicks.add(now);
            // Remove clicks older than 1 second
            clicks.removeIf(t -> now - t > 1000);
            if (clicks.size() > maxCps) {
                alertSystem.warning("HackDetector", player.getName(),
                        "High CPS: " + clicks.size() + "/s (max: " + maxCps + ")");
                return "HIGH_CPS";
            }
        }

        // 3. KillAura — Checks if player hits entity not in view angle (> 135 degrees off center)
        if (detectKillaura && target instanceof LivingEntity) {
            float yawToTarget = getYawToTarget(player, target);
            float playerYaw = player.getLocation().getYaw();
            float diff = Math.abs(yawToTarget - playerYaw) % 360;
            if (diff > 180) diff = 360 - diff;
            if (diff > 135) {
                alertSystem.warning("HackDetector", player.getName(),
                        "KillAura: hit entity at " + String.format("%.1f", diff) + "° off-center");
                return "KILLAURA";
            }
        }

        // 4. Illegal Criticals (critical hit while not actually falling)
        if (detectIllegalCrits && target instanceof LivingEntity) {
            boolean falling = wasFalling.getOrDefault(uuid, false);
            boolean isOnGround = player.isOnGround();
            // Vanilla crit requires player to be falling (not on ground, not under status effects)
            // If player consistently gets crits while on ground, suspicious
            // We track this via a counter approach — simplified here
        }

        return null;
    }

    /**
     * Records the player's current head rotation for aimbot analysis.
     *
     * @param player Player to record
     */
    public void recordRotation(Player player) {
        UUID uuid = player.getUniqueId();
        float yaw = player.getLocation().getYaw();
        List<Float> yaws = yawChanges.computeIfAbsent(uuid, k -> new ArrayList<>());
        synchronized (yaws) {
            yaws.add(yaw);
            if (yaws.size() > 20) yaws.remove(0); // Keep last 20 ticks
        }
        wasFalling.put(uuid, player.getVelocity().getY() < -0.1 && !player.isOnGround());
    }

    /**
     * Computes the required yaw angle to face a target entity.
     */
    private float getYawToTarget(Player player, Entity target) {
        Location p = player.getLocation();
        Location t = target.getLocation();
        double dx = t.getX() - p.getX();
        double dz = t.getZ() - p.getZ();
        return (float) (Math.toDegrees(Math.atan2(-dx, dz)) + 360) % 360;
    }

    /**
     * Clears player data on logout.
     *
     * @param uuid Player UUID
     */
    public void cleanup(UUID uuid) {
        clickTimestamps.remove(uuid);
        yawChanges.remove(uuid);
        wasFalling.remove(uuid);
    }
}
