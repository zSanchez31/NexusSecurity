package nx.zsanchez.nexussecurity.modules.compliance;

import nx.zsanchez.nexussecurity.NexusSecurity;
import nx.zsanchez.nexussecurity.core.*;

import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

/**
 * Module 9: Compliance — Security Audit, Immutable Logging & Report Generation.
 * Provides auditing against CIS Benchmarks, immutable audit trails, and automatic reporting.
 */
public class Compliance implements SecurityModule {

    private final NexusSecurity plugin;
    private final Logger logger;
    private final DatabaseManager databaseManager;
    private final ThreadPoolManager threadPoolManager;

    private AuditLogger auditLogger;
    private ReportGenerator reportGenerator;
    private ComplianceChecklist complianceChecklist;
    private ScheduledFuture<?> reportTask;
    private boolean enabled = false;

    public Compliance(NexusSecurity plugin, DatabaseManager databaseManager, ThreadPoolManager threadPoolManager) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
        this.databaseManager = databaseManager;
        this.threadPoolManager = threadPoolManager;
    }

    @Override
    public String getName() { return "Compliance"; }

    @Override
    public String getDescription() { return "Immutable audit logging, log search, scheduled reports and compliance checklist."; }

    @Override
    public void enable() {
        if (enabled) return;
        this.auditLogger = new AuditLogger(plugin, databaseManager);
        this.reportGenerator = new ReportGenerator(plugin, databaseManager);
        this.complianceChecklist = new ComplianceChecklist(plugin);
        enabled = true;
        logger.info("[Compliance] Module enabled. Immutable audit trail active.");

        if (plugin.getConfig().getBoolean("modules.compliance.auto-export.enabled", false)) {
            int intervalDays = Math.max(1, plugin.getConfig().getInt("modules.compliance.auto-export.interval-days", 7));
            this.reportTask = threadPoolManager.scheduleAtFixedRate(
                    "ComplianceAutoReport",
                    () -> threadPoolManager.submit("ComplianceReport", reportGenerator::generateScheduledReport),
                    1,
                    intervalDays,
                    TimeUnit.DAYS
            );
            logger.info("[Compliance] Automatic report scheduled every " + intervalDays + "d.");
        }
    }

    @Override
    public void disable() {
        if (!enabled) return;
        if (reportTask != null && !reportTask.isCancelled()) {
            reportTask.cancel(false);
        }
        enabled = false;
        logger.info("[Compliance] Module disabled.");
    }

    @Override
    public boolean isEnabled() { return enabled; }

    public AuditLogger getAuditLogger() { return auditLogger; }
    public ReportGenerator getReportGenerator() { return reportGenerator; }
    public ComplianceChecklist getComplianceChecklist() { return complianceChecklist; }

    @Override
    public String getStatusSummary() {
        return "&aACTIVO &7| Audit Logging: &f" + (auditLogger != null && auditLogger.isLogAdminCommands());
    }
}
