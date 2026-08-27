package nx.zsanchez.nexussecurity.modules.threatintel;

import nx.zsanchez.nexussecurity.NexusSecurity;
import nx.zsanchez.nexussecurity.core.*;

import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

/**
 * Module 8: ThreatIntelligence — Global Threat Intelligence & Real-time Reputation Feeds.
 * Continuously syncs global threat databases and anonymously shares detected threat indicators.
 */
public class ThreatIntelligence implements SecurityModule {

    private final NexusSecurity plugin;
    private final Logger logger;
    private final AlertSystem alertSystem;
    private final CacheManager cacheManager;
    private final ThreadPoolManager threadPoolManager;

    private ThreatFeedSync threatFeedSync;
    private boolean enabled = false;
    private ScheduledFuture<?> syncTask;
    private int syncIntervalHours;

    public ThreatIntelligence(NexusSecurity plugin, AlertSystem alertSystem, CacheManager cacheManager,
                              ThreadPoolManager threadPoolManager) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
        this.alertSystem = alertSystem;
        this.cacheManager = cacheManager;
        this.threadPoolManager = threadPoolManager;
    }

    @Override
    public String getName() { return "ThreatIntelligence"; }

    @Override
    public String getDescription() { return "Synchronizes global threat feeds and updates IP reputation scores."; }

    @Override
    public void enable() {
        if (enabled) return;
        this.threatFeedSync = new ThreatFeedSync(plugin, alertSystem, cacheManager);
        this.syncIntervalHours = plugin.getConfig().getInt("modules.threat-intelligence.sync-interval-hours", 6);
        enabled = true;

        this.syncTask = threadPoolManager.scheduleAtFixedRate(
                "ThreatFeedSync",
                () -> threatFeedSync.syncFeeds(),
                1,
                syncIntervalHours,
                TimeUnit.HOURS
        );

        logger.info("[ThreatIntelligence] Module enabled. Sync every " + syncIntervalHours + "h.");
    }

    @Override
    public void disable() {
        if (!enabled) return;
        if (syncTask != null && !syncTask.isCancelled()) {
            syncTask.cancel(false);
        }
        enabled = false;
        logger.info("[ThreatIntelligence] Module disabled.");
    }

    @Override
    public boolean isEnabled() { return enabled; }

    public ThreatFeedSync getThreatFeedSync() { return threatFeedSync; }

    @Override
    public double getResourceUsageScore() {
        return Math.min(1.0, cacheManager.getThreatScoreCacheSize() / 10000.0);
    }

    @Override
    public String getStatusSummary() {
        return "&aACTIVO &7| Sync interval: &f" + syncIntervalHours + "h";
    }
}
