package nx.zsanchez.nexussecurity.modules.autopilot;

import nx.zsanchez.nexussecurity.NexusSecurity;
import nx.zsanchez.nexussecurity.core.AlertSystem;
import nx.zsanchez.nexussecurity.core.EventBus;

import java.util.Map;
import java.util.logging.Logger;

/**
 * Automates policy execution and incident remediation based on event triggers.
 */
public class PlaybookEngine {

    private final NexusSecurity plugin;
    private final Logger logger;
    private final AlertSystem alertSystem;
    private final EventBus eventBus;
    private final EmergencyMode emergencyMode;

    private boolean fullyAutomatic;

    public PlaybookEngine(NexusSecurity plugin, AlertSystem alertSystem, EventBus eventBus, EmergencyMode emergencyMode) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
        this.alertSystem = alertSystem;
        this.eventBus = eventBus;
        this.emergencyMode = emergencyMode;
        loadConfig();
        registerListeners();
    }

    public void loadConfig() {
        this.fullyAutomatic = plugin.getConfig().getBoolean("modules.autopilot.fully-automatic", true);
    }

    private void registerListeners() {
        eventBus.subscribe(EventBus.EVENT_ANOMALY_DETECTED, this::handleAnomaly);
        eventBus.subscribe(EventBus.EVENT_FILE_MODIFIED, this::handleFileModification);
    }

    private void handleAnomaly(Map<String, Object> data) {
        if (!fullyAutomatic) return;
        Integer riskScore = (Integer) data.get("riskScore");
        if (riskScore != null && riskScore >= 85) {
            alertSystem.critical("Autopilot", "Playbook", "High anomaly risk score (" + riskScore + "). Triggering Emergency Playbook.");
            emergencyMode.activate();
        }
    }

    private void handleFileModification(Map<String, Object> data) {
        if (!fullyAutomatic) return;
        alertSystem.critical("Autopilot", "Playbook", "File tampering detected. Triggering Emergency Playbook.");
        emergencyMode.activate();
    }

    public boolean isFullyAutomatic() { return fullyAutomatic; }
}
