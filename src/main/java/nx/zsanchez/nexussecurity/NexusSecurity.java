package nx.zsanchez.nexussecurity;

import nx.zsanchez.nexussecurity.api.ApiValidator;
import nx.zsanchez.nexussecurity.api.SubscriptionManager;
import nx.zsanchez.nexussecurity.commands.SecurityCommand;
import nx.zsanchez.nexussecurity.core.*;
import nx.zsanchez.nexussecurity.listeners.*;
import nx.zsanchez.nexussecurity.modules.autopilot.Autopilot;
import nx.zsanchez.nexussecurity.modules.compliance.Compliance;
import nx.zsanchez.nexussecurity.modules.defenderai.DefenderAI;
import nx.zsanchez.nexussecurity.modules.guardian.Guardian;
import nx.zsanchez.nexussecurity.modules.hackdetector.HackDetector;
import nx.zsanchez.nexussecurity.modules.integrity.Integrity;
import nx.zsanchez.nexussecurity.modules.sentinel.Sentinel;
import nx.zsanchez.nexussecurity.modules.shield.Shield;
import nx.zsanchez.nexussecurity.modules.threatintel.ThreatIntelligence;
import nx.zsanchez.nexussecurity.modules.vault.Vault;
import nx.zsanchez.nexussecurity.modules.vulnerability.VulnerabilityCenter;
import nx.zsanchez.nexussecurity.util.HashUtil;
import nx.zsanchez.nexussecurity.util.MessageFormatter;
import nx.zsanchez.nexussecurity.web.WebPanel;
import org.bukkit.plugin.java.JavaPlugin;

import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * NexusSecurity — Professional Multilayer Security Platform for Minecraft Servers.
 *
 * <p>Main plugin entry point managing core services, module registrations,
 * database connectivity, subscription validation, and event listeners.</p>
 */
public class NexusSecurity extends JavaPlugin {

    private static NexusSecurity instance;

    private String serverId;
    private ThreadPoolManager threadPoolManager;
    private CacheManager cacheManager;
    private DatabaseManager databaseManager;
    private EventBus eventBus;
    private BatchWriter batchWriter;
    private AlertSystem alertSystem;
    private ExternalNotifier externalNotifier;
    private PerformanceMonitor performanceMonitor;
    private ModuleManager moduleManager;
    private MemoryWatchdog memoryWatchdog;
    private WebPanel webPanel;

    private ApiValidator apiValidator;
    private SubscriptionManager subscriptionManager;

    @Override
    public void onEnable() {
        instance = this;
        saveDefaultConfig();

        // 1. Initialize server ID
        this.serverId = getConfig().getString("server-id", UUID.randomUUID().toString());

        // 2. Initialize Core Infrastructure
        this.threadPoolManager = new ThreadPoolManager(this);
        this.cacheManager = new CacheManager(this);
        this.databaseManager = new DatabaseManager(this);
        this.eventBus = new EventBus(this);
        this.batchWriter = new BatchWriter(this, databaseManager, threadPoolManager);
        this.alertSystem = new AlertSystem(this, databaseManager, batchWriter);
        this.moduleManager = new ModuleManager(this);
        this.performanceMonitor = new PerformanceMonitor(this, eventBus, moduleManager);

        // 2b. Initialize Memory Watchdog (proactive JVM memory monitoring + warnings)
        this.memoryWatchdog = new MemoryWatchdog(this, alertSystem, eventBus);
        int memoryCheckInterval = getConfig().getInt("performance.memory-watchdog.check-interval-seconds", 15);
        threadPoolManager.scheduleAtFixedRate(
                "MemoryWatchdog", memoryWatchdog::check,
                memoryCheckInterval, memoryCheckInterval, TimeUnit.SECONDS);

        // 3. Connect Database (Async)
        threadPoolManager.submit("DBConnect", () -> {
            databaseManager.connect();
            batchWriter.start();
        });

        // 3b. Schedule periodic data-retention purge so the database never grows without bound.
        int purgeIntervalHours = getConfig().getInt("database.purge-interval-hours", 24);
        int retentionDays = getConfig().getInt("database.log-retention-days", 90);
        threadPoolManager.scheduleAtFixedRate(
                "DataRetention",
                () -> databaseManager.purgeOldData(retentionDays),
                purgeIntervalHours, purgeIntervalHours, TimeUnit.HOURS);

        // 3c. Start embedded web administration panel (if enabled in config)
        this.webPanel = new WebPanel(this);
        webPanel.start();

        // 3c-bis. External notifications (Discord/Telegram)
        this.externalNotifier = new ExternalNotifier(this, alertSystem);
        externalNotifier.loadConfig();
        externalNotifier.start();

        // 4. Start Performance Monitoring
        performanceMonitor.start(threadPoolManager);

        // 5. Register All 11 Security Modules
        registerModules();

        // 6. Initialize Subscription & API System
        this.apiValidator = new ApiValidator(this);
        this.subscriptionManager = new SubscriptionManager(this, apiValidator, moduleManager, eventBus, threadPoolManager);
        subscriptionManager.initializeAsync();

        // 7. Register Commands & Listeners
        var command = new SecurityCommand(this);
        Objects.requireNonNull(getCommand("security")).setExecutor(command);
        Objects.requireNonNull(getCommand("security")).setTabCompleter(command);

        getServer().getPluginManager().registerEvents(new PlayerConnectionListener(this), this);
        getServer().getPluginManager().registerEvents(new PlayerMoveListener(this), this);
        getServer().getPluginManager().registerEvents(new PlayerInteractListener(this), this);

        getLogger().info(MessageFormatter.stripColors(MessageFormatter.success(
                "NexusSecurity v" + getDescription().getVersion() + " initialized successfully.")));
    }

    @Override
    public void onDisable() {
        getLogger().info("[NexusSecurity] Shutting down security platform...");

        if (subscriptionManager != null) subscriptionManager.shutdown();
        if (externalNotifier != null) externalNotifier.stop();
        if (webPanel != null) webPanel.stop();
        if (moduleManager != null) moduleManager.disableAll();
        if (performanceMonitor != null) performanceMonitor.stop();
        if (batchWriter != null) batchWriter.stop();
        if (databaseManager != null) databaseManager.disconnect();
        if (cacheManager != null) cacheManager.invalidateAll();
        if (eventBus != null) eventBus.clearAll();
        if (threadPoolManager != null) threadPoolManager.shutdown();

        getLogger().info("[NexusSecurity] Platform disabled cleanly.");
    }

    /**
     * Registers all 11 security modules with the ModuleManager.
     */
    private void registerModules() {
        moduleManager.register(new Shield(this, cacheManager, databaseManager, alertSystem, eventBus, threadPoolManager));
        moduleManager.register(new Guardian(this, cacheManager, databaseManager, alertSystem, threadPoolManager));
        moduleManager.register(new Sentinel(this, alertSystem, performanceMonitor, threadPoolManager));
        moduleManager.register(new DefenderAI(this, alertSystem, eventBus, performanceMonitor, threadPoolManager));
        moduleManager.register(new Vault(this, alertSystem, threadPoolManager));
        moduleManager.register(new Integrity(this, alertSystem, databaseManager, threadPoolManager));
        moduleManager.register(new VulnerabilityCenter(this, alertSystem, threadPoolManager));
        moduleManager.register(new ThreatIntelligence(this, alertSystem, cacheManager, threadPoolManager));
        moduleManager.register(new Compliance(this, databaseManager, threadPoolManager));
        moduleManager.register(new Autopilot(this, alertSystem, eventBus));
        moduleManager.register(new HackDetector(this, alertSystem, databaseManager, eventBus));
    }

    public static NexusSecurity getInstance() { return instance; }
    public BatchWriter getBatchWriter() { return batchWriter; }
    public String getServerId() { return serverId; }
    public void setServerId(String id) { this.serverId = id; }
    public ThreadPoolManager getThreadPoolManager() { return threadPoolManager; }
    public CacheManager getCacheManager() { return cacheManager; }
    public DatabaseManager getDatabaseManager() { return databaseManager; }
    public EventBus getEventBus() { return eventBus; }
    public AlertSystem getAlertSystem() { return alertSystem; }
    public PerformanceMonitor getPerformanceMonitor() { return performanceMonitor; }
    public ModuleManager getModuleManager() { return moduleManager; }
    public MemoryWatchdog getMemoryWatchdog() { return memoryWatchdog; }
    public WebPanel getWebPanel() { return webPanel; }

    /**
     * Records a web-panel admin action to the audit log.
     */
    public void logAction(String actor, String action, String target, String result) {
        if (databaseManager != null) {
            databaseManager.insertAuditLog(actor, "WEB", action, target, result, null);
        }
    }
    public SubscriptionManager getSubscriptionManager() { return subscriptionManager; }
}
