package nx.zsanchez.nexussecurity.modules.autopilot;

import nx.zsanchez.nexussecurity.NexusSecurity;
import nx.zsanchez.nexussecurity.core.*;

import java.util.logging.Logger;

/**
 * Module 10: Autopilot — Automated Incident Response and Playbook Remediation.
 * Provides zero-touch incident remediation, process isolation, quarantine management, and emergency response.
 */
public class Autopilot implements SecurityModule {

    private final NexusSecurity plugin;
    private final Logger logger;
    private final AlertSystem alertSystem;
    private final EventBus eventBus;

    private EmergencyMode emergencyMode;
    private PlaybookEngine playbookEngine;
    private boolean enabled = false;

    public Autopilot(NexusSecurity plugin, AlertSystem alertSystem, EventBus eventBus) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
        this.alertSystem = alertSystem;
        this.eventBus = eventBus;
    }

    @Override
    public String getName() { return "Autopilot"; }

    @Override
    public String getDescription() { return "Automated incident response playbooks and emergency mode orchestration."; }

    @Override
    public void enable() {
        if (enabled) return;
        this.emergencyMode = new EmergencyMode(plugin, alertSystem);
        this.playbookEngine = new PlaybookEngine(plugin, alertSystem, eventBus, emergencyMode);
        enabled = true;
        logger.info("[Autopilot] Module enabled. Zero-touch remediation active.");
    }

    @Override
    public void disable() {
        if (!enabled) return;
        if (emergencyMode != null && emergencyMode.isActive()) {
            emergencyMode.deactivate();
        }
        enabled = false;
        logger.info("[Autopilot] Module disabled.");
    }

    @Override
    public boolean isEnabled() { return enabled; }

    public EmergencyMode getEmergencyMode() { return emergencyMode; }
    public PlaybookEngine getPlaybookEngine() { return playbookEngine; }

    @Override
    public String getStatusSummary() {
        return "&aACTIVO &7| Emergency: " + (emergencyMode != null && emergencyMode.isActive() ? "&cON" : "&aOFF");
    }
}
