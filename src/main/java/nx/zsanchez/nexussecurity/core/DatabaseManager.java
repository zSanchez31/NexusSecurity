package nx.zsanchez.nexussecurity.core;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import nx.zsanchez.nexussecurity.NexusSecurity;
import nx.zsanchez.nexussecurity.util.TimeUtil;

import java.io.File;
import java.sql.*;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

/**
 * Manages all database operations for NexusSecurity.
 * Supports SQLite (default, zero-config) and MySQL/PostgreSQL via HikariCP connection pool.
 *
 * <p>All schema creation is idempotent (uses CREATE TABLE IF NOT EXISTS).</p>
 * <p>All public methods that perform I/O should be called from async threads.</p>
 *
 * <p>Tables created:</p>
 * <ul>
 *   <li><b>security_events</b>: All security events with severity, source, description</li>
 *   <li><b>audit_log</b>: Immutable audit trail of player/admin actions</li>
 *   <li><b>ip_blacklist</b>: Persistent IP blocklist</li>
 *   <li><b>file_hashes</b>: Baseline file hashes for integrity verification</li>
 *   <li><b>player_violations</b>: HackDetector violation counts per player</li>
 *   <li><b>threat_indicators</b>: Known malicious IP/domain indicators</li>
 * </ul>
 */
public class DatabaseManager {

    private final NexusSecurity plugin;
    private final Logger logger;
    private HikariDataSource dataSource;
    private String dbType;

    /**
     * Initializes the database connection pool and creates all required tables.
     *
     * @param plugin The main plugin instance
     */
    public DatabaseManager(NexusSecurity plugin) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
    }

    /**
     * Establishes the database connection. Must be called before any queries.
     * This method performs I/O and should be called from an async context.
     *
     * @throws RuntimeException if connection fails
     */
    public void connect() {
        this.dbType = plugin.getConfig().getString("database.type", "sqlite").toLowerCase();
        HikariConfig config = new HikariConfig();

        if (dbType.equals("sqlite")) {
            // Ensure plugin data folder exists
            plugin.getDataFolder().mkdirs();
            String dbFile = plugin.getDataFolder() + File.separator +
                    plugin.getConfig().getString("database.sqlite-file", "nexussecurity.db");
            config.setDriverClassName("org.sqlite.JDBC");
            config.setJdbcUrl("jdbc:sqlite:" + dbFile);
            config.setMaximumPoolSize(1); // SQLite is single-writer
            config.setConnectionTestQuery("SELECT 1");
            logger.info("[Database] Using SQLite: " + dbFile);
        } else {
            // MySQL / PostgreSQL
            String host = plugin.getConfig().getString("database.mysql.host", "localhost");
            int port = plugin.getConfig().getInt("database.mysql.port", 3306);
            String database = plugin.getConfig().getString("database.mysql.database", "nexussecurity");
            String username = plugin.getConfig().getString("database.mysql.username", "nexussecurity");
            String password = plugin.getConfig().getString("database.mysql.password", "");

            if (dbType.equals("mysql")) {
                config.setJdbcUrl("jdbc:mysql://" + host + ":" + port + "/" + database +
                        "?useSSL=false&serverTimezone=UTC&characterEncoding=UTF-8");
                config.setDriverClassName("com.mysql.cj.jdbc.Driver");
            } else {
                config.setJdbcUrl("jdbc:postgresql://" + host + ":" + port + "/" + database);
                config.setDriverClassName("org.postgresql.Driver");
            }

            config.setUsername(username);
            config.setPassword(password);
            config.setMaximumPoolSize(plugin.getConfig().getInt("database.mysql.pool-size", 10));
            config.setConnectionTimeout(plugin.getConfig().getLong("database.mysql.connection-timeout-ms", 30000));
            config.setIdleTimeout(plugin.getConfig().getLong("database.mysql.idle-timeout-ms", 600000));
            config.setMaxLifetime(plugin.getConfig().getLong("database.mysql.max-lifetime-ms", 1800000));
            logger.info("[Database] Using " + dbType.toUpperCase() + " at " + host + ":" + port + "/" + database);
        }

        // Common HikariCP settings
        config.setPoolName("NexusSecurity-DB");
        config.addDataSourceProperty("cachePrepStmts", "true");
        config.addDataSourceProperty("prepStmtCacheSize", "250");
        config.addDataSourceProperty("prepStmtCacheSqlLimit", "2048");

        this.dataSource = new HikariDataSource(config);
        createTables();
        logger.info("[Database] Connected successfully.");
    }

    /**
     * Creates all required tables if they don't already exist.
     */
    private void createTables() {
        String createSecurityEvents = """
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp BIGINT NOT NULL,
                    severity VARCHAR(16) NOT NULL,
                    module VARCHAR(64) NOT NULL,
                    source VARCHAR(128),
                    description TEXT NOT NULL,
                    data TEXT,
                    resolved BOOLEAN DEFAULT 0
                )""";

        String createAuditLog = """
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp BIGINT NOT NULL,
                    actor VARCHAR(128) NOT NULL,
                    actor_type VARCHAR(32) NOT NULL,
                    action VARCHAR(256) NOT NULL,
                    target VARCHAR(256),
                    result VARCHAR(64),
                    ip_address VARCHAR(64),
                    server_id VARCHAR(128)
                )""";

        String createIpBlacklist = """
                CREATE TABLE IF NOT EXISTS ip_blacklist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address VARCHAR(64) NOT NULL UNIQUE,
                    reason TEXT,
                    source VARCHAR(64),
                    added_at BIGINT NOT NULL,
                    expires_at BIGINT,
                    threat_score INTEGER DEFAULT 0
                )""";

        String createFileHashes = """
                CREATE TABLE IF NOT EXISTS file_hashes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path VARCHAR(512) NOT NULL UNIQUE,
                    sha256_hash VARCHAR(64) NOT NULL,
                    file_size BIGINT,
                    last_verified BIGINT NOT NULL,
                    baseline_set BOOLEAN DEFAULT 1
                )""";

        String createPlayerViolations = """
                CREATE TABLE IF NOT EXISTS player_violations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    player_uuid VARCHAR(36) NOT NULL,
                    player_name VARCHAR(64) NOT NULL,
                    violation_type VARCHAR(64) NOT NULL,
                    violation_count INTEGER DEFAULT 1,
                    last_violation BIGINT NOT NULL,
                    details TEXT,
                    actioned BOOLEAN DEFAULT 0
                )""";

        String createThreatIndicators = """
                CREATE TABLE IF NOT EXISTS threat_indicators (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    indicator VARCHAR(256) NOT NULL UNIQUE,
                    indicator_type VARCHAR(32) NOT NULL,
                    threat_score INTEGER NOT NULL,
                    source VARCHAR(128),
                    added_at BIGINT NOT NULL,
                    expires_at BIGINT,
                    description TEXT
                )""";

        // For MySQL, replace AUTOINCREMENT with AUTO_INCREMENT
        if (!dbType.equals("sqlite")) {
            createSecurityEvents = createSecurityEvents.replace("AUTOINCREMENT", "AUTO_INCREMENT");
            createAuditLog = createAuditLog.replace("AUTOINCREMENT", "AUTO_INCREMENT");
            createIpBlacklist = createIpBlacklist.replace("AUTOINCREMENT", "AUTO_INCREMENT");
            createFileHashes = createFileHashes.replace("AUTOINCREMENT", "AUTO_INCREMENT");
            createPlayerViolations = createPlayerViolations.replace("AUTOINCREMENT", "AUTO_INCREMENT");
            createThreatIndicators = createThreatIndicators.replace("AUTOINCREMENT", "AUTO_INCREMENT");
        }

        try (Connection conn = getConnection();
             Statement stmt = conn.createStatement()) {
            stmt.execute(createSecurityEvents);
            stmt.execute(createAuditLog);
            stmt.execute(createIpBlacklist);
            stmt.execute(createFileHashes);
            stmt.execute(createPlayerViolations);
            stmt.execute(createThreatIndicators);

            // Create performance indices
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_events_severity ON security_events(severity)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_blacklist_ip ON ip_blacklist(ip_address)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_violations_uuid ON player_violations(player_uuid)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_threat_indicator ON threat_indicators(indicator)");

            logger.info("[Database] All tables and indices created successfully.");
        } catch (SQLException e) {
            logger.severe("[Database] Failed to create tables: " + e.getMessage());
            throw new RuntimeException("Database table creation failed", e);
        }
    }

    /**
     * Returns a connection from the pool. Always close in a try-with-resources block.
     *
     * @return A database connection
     * @throws SQLException if the pool is exhausted or unavailable
     */
    public Connection getConnection() throws SQLException {
        if (dataSource == null || dataSource.isClosed()) {
            throw new SQLException("DataSource is not initialized or has been closed.");
        }
        return dataSource.getConnection();
    }

    /**
     * Inserts a security event into the database.
     *
     * @param severity    Severity level (INFO, WARNING, CRITICAL)
     * @param module      Module that generated the event
     * @param source      Source identifier (IP, player name, file path)
     * @param description Human-readable description
     * @param data        Optional JSON data for additional context
     */
    public void insertSecurityEvent(String severity, String module, String source,
                                    String description, String data) {
        String sql = "INSERT INTO security_events(timestamp, severity, module, source, description, data) VALUES(?,?,?,?,?,?)";
        try (Connection conn = getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setLong(1, System.currentTimeMillis());
            ps.setString(2, severity);
            ps.setString(3, module);
            ps.setString(4, source);
            ps.setString(5, description);
            ps.setString(6, data);
            ps.executeUpdate();
        } catch (SQLException e) {
            logger.warning("[Database] Failed to insert security event: " + e.getMessage());
        }
    }

    /**
     * Inserts an audit log entry.
     *
     * @param actor     Who performed the action
     * @param actorType Type of actor (PLAYER, ADMIN, SYSTEM)
     * @param action    Description of the action
     * @param target    Target of the action (may be null)
     * @param result    Result (SUCCESS, FAILURE, BLOCKED)
     * @param ipAddress Actor's IP address
     */
    public void insertAuditLog(String actor, String actorType, String action,
                               String target, String result, String ipAddress) {
        String sql = "INSERT INTO audit_log(timestamp, actor, actor_type, action, target, result, ip_address, server_id) VALUES(?,?,?,?,?,?,?,?)";
        try (Connection conn = getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setLong(1, System.currentTimeMillis());
            ps.setString(2, actor);
            ps.setString(3, actorType);
            ps.setString(4, action);
            ps.setString(5, target);
            ps.setString(6, result);
            ps.setString(7, ipAddress);
            ps.setString(8, plugin.getServerId());
            ps.executeUpdate();
        } catch (SQLException e) {
            logger.warning("[Database] Failed to insert audit log: " + e.getMessage());
        }
    }

    /**
     * Adds an IP to the blacklist.
     *
     * @param ip         The IP address to blacklist
     * @param reason     Reason for blacklisting
     * @param source     Source that detected this IP
     * @param expiresAt  Expiry timestamp in epoch millis, or -1 for permanent
     * @param threatScore Threat score 0-100
     */
    public void blacklistIp(String ip, String reason, String source, long expiresAt, int threatScore) {
        String sql = "INSERT OR REPLACE INTO ip_blacklist(ip_address, reason, source, added_at, expires_at, threat_score) VALUES(?,?,?,?,?,?)";
        try (Connection conn = getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, ip);
            ps.setString(2, reason);
            ps.setString(3, source);
            ps.setLong(4, System.currentTimeMillis());
            ps.setLong(5, expiresAt);
            ps.setInt(6, threatScore);
            ps.executeUpdate();
        } catch (SQLException e) {
            logger.warning("[Database] Failed to blacklist IP: " + e.getMessage());
        }
    }

    /**
     * Checks if an IP is in the blacklist (and not expired).
     *
     * @param ip The IP to check
     * @return true if the IP is blacklisted
     */
    public boolean isBlacklisted(String ip) {
        String sql = "SELECT expires_at FROM ip_blacklist WHERE ip_address = ? AND (expires_at = -1 OR expires_at > ?)";
        try (Connection conn = getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, ip);
            ps.setLong(2, System.currentTimeMillis());
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        } catch (SQLException e) {
            logger.warning("[Database] Failed to check blacklist for IP " + ip + ": " + e.getMessage());
            return false;
        }
    }

    /**
     * Lists blacklist entries (most recently added first).
     *
     * @param limit Maximum number of rows
     * @return List of rows as maps
     */
    public List<Map<String, Object>> listBlacklist(int limit) {
        List<Map<String, Object>> out = new ArrayList<>();
        String sql = "SELECT ip_address, reason, source, added_at, expires_at, threat_score " +
                "FROM ip_blacklist ORDER BY added_at DESC LIMIT ?";
        try (Connection conn = getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, limit);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) out.add(rowToMap(rs));
            }
        } catch (SQLException e) {
            logger.warning("[Database] Failed to list blacklist: " + e.getMessage());
        }
        return out;
    }

    /**
     * Removes an IP from the blacklist.
     *
     * @param ip The IP to remove
     * @return true if a row was deleted
     */
    public boolean removeFromBlacklist(String ip) {
        String sql = "DELETE FROM ip_blacklist WHERE ip_address = ?";
        try (Connection conn = getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, ip);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            logger.warning("[Database] Failed to remove IP from blacklist " + ip + ": " + e.getMessage());
            return false;
        }
    }

    /**
     * Returns recent audit log entries (most recent first).
     *
     * @param limit Maximum number of rows
     * @return List of rows as maps
     */
    public List<Map<String, Object>> queryAuditLog(int limit) {
        return queryAuditLog("", "", "", -1, -1, limit, 0);
    }

    /**
     * Returns audit log entries filtered and paginated.
     *
     * @param actor  Substring filter on actor (may be blank)
     * @param action Substring filter on action (may be blank)
     * @param search Substring filter on target/result/actor (may be blank)
     * @param from   Minimum timestamp (epoch ms, or &lt;0 to ignore)
     * @param to     Maximum timestamp (epoch ms, or &lt;0 to ignore)
     * @param limit  Page size
     * @param offset Row offset
     * @return List of rows as maps
     */
    public List<Map<String, Object>> queryAuditLog(String actor, String action, String search,
                                                   long from, long to, int limit, int offset) {
        List<Map<String, Object>> out = new ArrayList<>();
        StringBuilder sql = new StringBuilder(
                "SELECT id, timestamp, actor, actor_type, action, target, result, ip_address FROM audit_log WHERE 1=1");
        List<Object> params = new ArrayList<>();
        if (actor != null && !actor.isEmpty()) { sql.append(" AND actor LIKE ?"); params.add("%" + actor + "%"); }
        if (action != null && !action.isEmpty()) { sql.append(" AND action LIKE ?"); params.add("%" + action + "%"); }
        if (search != null && !search.isEmpty()) {
            sql.append(" AND (target LIKE ? OR result LIKE ? OR actor LIKE ?)");
            params.add("%" + search + "%"); params.add("%" + search + "%"); params.add("%" + search + "%");
        }
        if (from > 0) { sql.append(" AND timestamp >= ?"); params.add(from); }
        if (to > 0) { sql.append(" AND timestamp <= ?"); params.add(to); }
        sql.append(" ORDER BY timestamp DESC LIMIT ? OFFSET ?");
        try (Connection conn = getConnection();
             PreparedStatement ps = conn.prepareStatement(sql.toString())) {
            int i = 1;
            for (Object p : params) {
                if (p instanceof String) ps.setString(i, (String) p);
                else ps.setLong(i, (Long) p);
                i++;
            }
            ps.setInt(i++, limit);
            ps.setInt(i, offset);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) out.add(rowToMap(rs));
            }
        } catch (SQLException e) {
            logger.warning("[Database] Failed to read audit log: " + e.getMessage());
        }
        return out;
    }

    private Map<String, Object> rowToMap(ResultSet rs) throws SQLException {
        Map<String, Object> map = new LinkedHashMap<>();
        ResultSetMetaData md = rs.getMetaData();
        for (int i = 1; i <= md.getColumnCount(); i++) {
            map.put(md.getColumnName(i), rs.getObject(i));
        }
        return map;
    }

    /**
     * Returns the violation history for a specific player.
     *
     * @param uuid Player UUID
     * @return List of violation rows
     */
    public List<Map<String, Object>> queryViolations(java.util.UUID uuid) {
        List<Map<String, Object>> out = new ArrayList<>();
        String sql = "SELECT violation_type, violation_count, last_violation, details, actioned " +
                "FROM player_violations WHERE player_uuid = ? ORDER BY last_violation DESC";
        try (Connection conn = getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, uuid.toString());
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) out.add(rowToMap(rs));
            }
        } catch (SQLException e) {
            logger.warning("[Database] Failed to read violations for " + uuid + ": " + e.getMessage());
        }
        return out;
    }

    /**
     * Saves or updates a file hash baseline entry.
     *
     * @param filePath Absolute path to the file
     * @param hash     SHA-256 hex hash
     * @param fileSize File size in bytes
     */
    public void saveFileHash(String filePath, String hash, long fileSize) {
        String sql = "INSERT OR REPLACE INTO file_hashes(file_path, sha256_hash, file_size, last_verified) VALUES(?,?,?,?)";
        try (Connection conn = getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, filePath);
            ps.setString(2, hash);
            ps.setLong(3, fileSize);
            ps.setLong(4, System.currentTimeMillis());
            ps.executeUpdate();
        } catch (SQLException e) {
            logger.warning("[Database] Failed to save file hash: " + e.getMessage());
        }
    }

    /**
     * Returns the stored hash for a file, or null if not in baseline.
     *
     * @param filePath Absolute file path
     * @return SHA-256 hex hash, or null
     */
    public String getFileHash(String filePath) {
        String sql = "SELECT sha256_hash FROM file_hashes WHERE file_path = ?";
        try (Connection conn = getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, filePath);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getString("sha256_hash") : null;
            }
        } catch (SQLException e) {
            logger.warning("[Database] Failed to get file hash: " + e.getMessage());
            return null;
        }
    }

    /**
     * Records or increments a HackDetector violation for a player.
     *
     * @param playerUuid    Player UUID string
     * @param playerName    Player name
     * @param violationType Type of violation detected
     * @param details       Additional details
     */
    public void recordViolation(String playerUuid, String playerName,
                                String violationType, String details) {
        // Try to increment existing record, or insert new
        String selectSql = "SELECT id, violation_count FROM player_violations WHERE player_uuid=? AND violation_type=? AND actioned=0";
        try (Connection conn = getConnection();
             PreparedStatement selectPs = conn.prepareStatement(selectSql)) {
            selectPs.setString(1, playerUuid);
            selectPs.setString(2, violationType);
            try (ResultSet rs = selectPs.executeQuery()) {
                if (rs.next()) {
                    int id = rs.getInt("id");
                    int count = rs.getInt("violation_count") + 1;
                    String updateSql = "UPDATE player_violations SET violation_count=?, last_violation=?, details=? WHERE id=?";
                    try (PreparedStatement updatePs = conn.prepareStatement(updateSql)) {
                        updatePs.setInt(1, count);
                        updatePs.setLong(2, System.currentTimeMillis());
                        updatePs.setString(3, details);
                        updatePs.setInt(4, id);
                        updatePs.executeUpdate();
                    }
                } else {
                    String insertSql = "INSERT INTO player_violations(player_uuid, player_name, violation_type, violation_count, last_violation, details) VALUES(?,?,?,1,?,?)";
                    try (PreparedStatement insertPs = conn.prepareStatement(insertSql)) {
                        insertPs.setString(1, playerUuid);
                        insertPs.setString(2, playerName);
                        insertPs.setString(3, violationType);
                        insertPs.setLong(4, System.currentTimeMillis());
                        insertPs.setString(5, details);
                        insertPs.executeUpdate();
                    }
                }
            }
        } catch (SQLException e) {
            logger.warning("[Database] Failed to record violation: " + e.getMessage());
        }
    }

    /**
     * Returns the total active violation count for a player across all types.
     *
     * @param playerUuid Player UUID string
     * @return Total violation count
     */
    public int getViolationCount(String playerUuid) {
        String sql = "SELECT COALESCE(SUM(violation_count), 0) AS total FROM player_violations WHERE player_uuid=? AND actioned=0";
        try (Connection conn = getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, playerUuid);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getInt("total") : 0;
            }
        } catch (SQLException e) {
            logger.warning("[Database] Failed to get violation count: " + e.getMessage());
            return 0;
        }
    }

    /**
     * Inserts or updates a threat indicator (malicious IP/domain) in the database.
     *
     * @param indicator  The IP address or domain
     * @param type       Indicator type ("IP", "DOMAIN", "URL")
     * @param threatScore Threat score 0-100
     * @param source     Source of the indicator (e.g. "THREAT-FEED")
     * @param expiresAt  Expiry timestamp in epoch millis, or -1 for permanent
     * @param description Optional description
     */
    public void insertThreatIndicator(String indicator, String type, int threatScore,
                                      String source, long expiresAt, String description) {
        String sql = "INSERT OR REPLACE INTO threat_indicators" +
                "(indicator, indicator_type, threat_score, source, added_at, expires_at, description) VALUES(?,?,?,?,?,?,?)";
        try (Connection conn = getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, indicator);
            ps.setString(2, type);
            ps.setInt(3, threatScore);
            ps.setString(4, source);
            ps.setLong(5, System.currentTimeMillis());
            ps.setLong(6, expiresAt);
            ps.setString(7, description);
            ps.executeUpdate();
        } catch (SQLException e) {
            logger.warning("[Database] Failed to store threat indicator " + indicator + ": " + e.getMessage());
        }
    }

    /**
     * Returns the threat score (0-100) for an indicator that is still valid (not expired).
     *
     * @param indicator IP or domain
     * @return Threat score, or null if no active indicator exists
     */
    public Integer getThreatIndicatorScore(String indicator) {
        String sql = "SELECT threat_score FROM threat_indicators WHERE indicator = ? AND (expires_at IS NULL OR expires_at > ?)";
        try (Connection conn = getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, indicator);
            ps.setLong(2, System.currentTimeMillis());
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getInt("threat_score") : null;
            }
        } catch (SQLException e) {
            logger.warning("[Database] Failed to query threat score for " + indicator + ": " + e.getMessage());
            return null;
        }
    }

    /**
     * Purges records older than the configured retention period.
     * Should be called periodically from an async thread.
     *
     * @param retentionDays Days to keep records
     */
    public void purgeOldData(int retentionDays) {
        long cutoff = TimeUtil.daysAgo(retentionDays);
        try (Connection conn = getConnection();
             Statement stmt = conn.createStatement()) {
            int deletedEvents = stmt.executeUpdate("DELETE FROM security_events WHERE timestamp < " + cutoff);
            int deletedAudit = stmt.executeUpdate("DELETE FROM audit_log WHERE timestamp < " + cutoff);
            // Clean expired blacklist entries
            stmt.executeUpdate("DELETE FROM ip_blacklist WHERE expires_at > 0 AND expires_at < " + System.currentTimeMillis());
            // Clean expired threat indicators
            stmt.executeUpdate("DELETE FROM threat_indicators WHERE expires_at > 0 AND expires_at < " + System.currentTimeMillis());
            logger.info("[Database] Purged old data: " + deletedEvents + " events, " + deletedAudit + " audit entries.");
        } catch (SQLException e) {
            logger.warning("[Database] Failed to purge old data: " + e.getMessage());
        }
    }

    /**
     * Gracefully closes the connection pool.
     */
    public void disconnect() {
        if (dataSource != null && !dataSource.isClosed()) {
            dataSource.close();
            logger.info("[Database] Connection pool closed.");
        }
    }

    /**
     * Returns whether the database is connected and usable.
     *
     * @return true if connected
     */
    public boolean isConnected() {
        return dataSource != null && !dataSource.isClosed();
    }
}
