package nx.zsanchez.nexussecurity.modules.sentinel;

import nx.zsanchez.nexussecurity.NexusSecurity;
import nx.zsanchez.nexussecurity.core.AlertSystem;
import org.bukkit.Bukkit;

import java.net.ServerSocket;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Logger;

/**
 * Subsystem of Sentinel for tracking open ports and connection activity.
 */
public class ConnectionMonitor {

    private final NexusSecurity plugin;
    private final Logger logger;
    private final AlertSystem alertSystem;

    private boolean monitorPorts;
    private boolean monitorConnections;

    public ConnectionMonitor(NexusSecurity plugin, AlertSystem alertSystem) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
        this.alertSystem = alertSystem;
        loadConfig();
    }

    public void loadConfig() {
        this.monitorPorts = plugin.getConfig().getBoolean("modules.sentinel.monitor-ports", true);
        this.monitorConnections = plugin.getConfig().getBoolean("modules.sentinel.monitor-connections", true);
    }

    /**
     * Checks if common dangerous ports are unexpectedly open or bound locally.
     */
    public void checkPorts() {
        if (!monitorPorts) return;
        int[] portsToCheck = {22, 21, 3306, 5432, 27017, 6379, 8080, 8888};

        for (int port : portsToCheck) {
            // Ignore server's own port
            if (port == Bukkit.getPort()) continue;

            try (ServerSocket socket = new ServerSocket(port)) {
                // If we can bind, port is NOT currently used (clean)
            } catch (Exception e) {
                // Port is already in use by another process
                alertSystem.info("Sentinel", "PortCheck", "Port " + port + " is active/bound on host.");
            }
        }
    }
}
