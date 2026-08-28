package nx.zsanchez.nexussecurity.web;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import nx.zsanchez.nexussecurity.NexusSecurity;
import nx.zsanchez.nexussecurity.core.AlertSystem;
import nx.zsanchez.nexussecurity.core.DatabaseManager;
import nx.zsanchez.nexussecurity.core.ModuleManager;
import nx.zsanchez.nexussecurity.core.PerformanceMonitor;
import nx.zsanchez.nexussecurity.api.SubscriptionManager;
import nx.zsanchez.nexussecurity.core.SecurityModule;
import nx.zsanchez.nexussecurity.modules.autopilot.Autopilot;
import nx.zsanchez.nexussecurity.modules.autopilot.EmergencyMode;
import nx.zsanchez.nexussecurity.modules.guardian.Guardian;
import nx.zsanchez.nexussecurity.modules.hackdetector.HackDetector;
import nx.zsanchez.nexussecurity.modules.shield.Shield;
import nx.zsanchez.nexussecurity.modules.shield.RateLimiter;
import nx.zsanchez.nexussecurity.modules.vault.Vault;
import nx.zsanchez.nexussecurity.util.MessageFormatter;
import org.bukkit.BanList;
import org.bukkit.Bukkit;
import org.bukkit.event.Listener;
import org.bukkit.event.player.AsyncPlayerChatEvent;
import org.bukkit.ChatColor;
import org.bukkit.OfflinePlayer;
import org.bukkit.entity.Player;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;
import org.bukkit.potion.PotionEffect;

import java.io.IOException;
import java.io.File;
import java.io.OutputStream;
import java.lang.management.ManagementFactory;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileStore;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * Embedded web administration panel for NexusSecurity.
 *
 * <p>Uses only the JDK built-in {@link HttpServer} (no external web framework). Every access to
 * the Bukkit/Player API is performed on the main thread via
 * {@link Bukkit#getScheduler()}.read/run, since the HTTP handler threads are not the main thread.</p>
 *
 * <p>Features: login (optional password), live dashboard with TPS/RAM charts, module control,
 * player management (kick/ban/temp-ban/warn), IP blacklist management, audit & events viewers
 * with CSV export, emergency-mode toggle, and HackDetector suspects view.</p>
 */
public class WebPanel {

    public static final String DEFAULT_PASSWORD = "NexusSecurity123";

    private final NexusSecurity plugin;
    private final Gson gson = new GsonBuilder().create();

    private boolean enabled = false;
    private int port = 25580;
    private String bindAddress = "0.0.0.0";
    private String configuredHost = "";
    private boolean requirePassword = true;
    private String password = DEFAULT_PASSWORD;
    private int sessionTimeoutMinutes = 60;
    private String publicIpUrl = "https://api.ipify.org";
    private int maxFailedLogins = 5;
    private int lockoutMinutes = 10;

    private HttpServer server;
    private boolean running = false;

    private final Map<String, String> sessions = new ConcurrentHashMap<>();
    private final Map<String, String> sessionRole = new ConcurrentHashMap<>();
    private final Map<String, UserInfo> users = new ConcurrentHashMap<>();
    private boolean multiUser = false;
    private boolean twoFactor = false;
    private String totpSecret = "";
    private final Map<String, Integer> failedAttempts = new ConcurrentHashMap<>();
    private final Map<String, Long> lockUntil = new ConcurrentHashMap<>();

    private record UserInfo(String name, String hash, String role) {}

    private String cachedPanelUrl;

    private final java.util.List<SseClient> sseClients = new java.util.concurrent.CopyOnWriteArrayList<>();
    private java.util.function.Consumer<AlertSystem.AlertEntry> sseConsumer;

    private final java.util.Set<java.util.UUID> frozenPlayers = java.util.concurrent.ConcurrentHashMap.newKeySet();
    private final java.util.Set<java.util.UUID> mutedPlayers = java.util.concurrent.ConcurrentHashMap.newKeySet();

    private final java.util.concurrent.ConcurrentLinkedDeque<String> consoleLines = new java.util.concurrent.ConcurrentLinkedDeque<>();
    private final java.util.List<SseClient> consoleClients = new java.util.concurrent.CopyOnWriteArrayList<>();
    private java.util.logging.Handler consoleHandler;
    private static final int MAX_CONSOLE_LINES = 500;

    public WebPanel(NexusSecurity plugin) {
        this.plugin = plugin;
    }

    // ============================================================
    // Lifecycle
    // ============================================================

    public void start() {
        loadConfig();
        if (!enabled) {
            plugin.getLogger().info("[WebPanel] Desactivado (web-panel.enabled=false).");
            return;
        }
        if (requirePassword && DEFAULT_PASSWORD.equals(password)) {
            plugin.getLogger().warning("[WebPanel] Usando la contraseña por defecto ("
                    + DEFAULT_PASSWORD + "). ¡Cámbiala en config.yml!");
        }
        try {
            String bind = "0.0.0.0".equals(bindAddress) ? "0.0.0.0" : bindAddress;
            server = HttpServer.create(new InetSocketAddress(bind, port), 0);
            server.createContext("/", this::handle);
            server.setExecutor(Executors.newCachedThreadPool());
            server.start();
            running = true;
            cachedPanelUrl = resolvePanelUrl();
            plugin.getLogger().info("[WebPanel] Panel web disponible en " + cachedPanelUrl);
            this.sseConsumer = e -> {
                String data = "data: " + gson.toJson(java.util.Map.of(
                        "timestamp", e.timestamp(), "severity", e.severity(),
                        "module", e.module(), "source", e.source(), "message", e.description())) + "\n\n";
                for (SseClient c : sseClients) c.send(data);
            };
            plugin.getAlertSystem().subscribe(sseConsumer);
            try { Bukkit.getPluginManager().registerEvents(new WebPanelListener(), plugin); } catch (Exception ignored) {}
            this.consoleHandler = new java.util.logging.Handler() {
                @Override
                public void publish(java.util.logging.LogRecord record) {
                    String line = "[" + record.getLevel().getName() + "] " + record.getMessage();
                    consoleLines.addLast(line);
                    while (consoleLines.size() > MAX_CONSOLE_LINES) consoleLines.pollFirst();
                    String data = "data: " + gson.toJson(java.util.Map.of("line", line)) + "\n\n";
                    for (SseClient c : consoleClients) c.send(data);
                }
                @Override public void flush() {}
                @Override public void close() throws SecurityException {}
            };
            try { Bukkit.getServer().getLogger().addHandler(consoleHandler); } catch (Exception ignored) {}
        } catch (Exception e) {
            plugin.getLogger().severe("[WebPanel] No se pudo iniciar: " + e.getMessage());
        }
    }

    public void stop() {
        if (sseConsumer != null) {
            plugin.getAlertSystem().unsubscribe(sseConsumer);
            sseConsumer = null;
        }
        if (consoleHandler != null) {
            try { Bukkit.getServer().getLogger().removeHandler(consoleHandler); } catch (Exception ignored) {}
            consoleHandler = null;
        }
        for (SseClient c : consoleClients) c.close();
        consoleClients.clear();
        for (SseClient c : sseClients) c.close();
        sseClients.clear();
        if (server != null) {
            try { server.stop(0); } catch (Exception ignored) {}
        }
        running = false;
        sessions.clear();
        sessionRole.clear();
    }

    public void reload() {
        boolean wasRunning = running;
        stop();
        loadConfig();
        if (enabled) {
            start();
            if (wasRunning && !running) {
                plugin.getLogger().warning("[WebPanel] Reinicio falló tras recargar config.");
            }
        } else {
            plugin.getLogger().info("[WebPanel] Desactivado tras recargar config.");
        }
    }

    private void loadConfig() {
        var cfg = plugin.getConfig();
        enabled = cfg.getBoolean("web-panel.enabled", false);
        port = cfg.getInt("web-panel.port", 25580);
        bindAddress = cfg.getString("web-panel.bind-address", "0.0.0.0");
        configuredHost = cfg.getString("web-panel.host", "");
        requirePassword = cfg.getBoolean("web-panel.require-password", true);
        password = cfg.getString("web-panel.password", DEFAULT_PASSWORD);
        sessionTimeoutMinutes = cfg.getInt("web-panel.session-timeout-minutes", 60);
        publicIpUrl = cfg.getString("web-panel.public-ip-url", "https://api.ipify.org");
        maxFailedLogins = cfg.getInt("web-panel.max-failed-logins", 5);
        lockoutMinutes = cfg.getInt("web-panel.lockout-minutes", 10);

        // Users / roles / 2FA
        var usersSec = cfg.getConfigurationSection("web-panel.users");
        multiUser = usersSec != null && !usersSec.getKeys(false).isEmpty();
        users.clear();
        if (multiUser) {
            for (String name : usersSec.getKeys(false)) {
                String pw = usersSec.getString(name + ".password", "");
                String role = usersSec.getString(name + ".role", "viewer");
                users.put(name.toLowerCase(), new UserInfo(name, hash(pw), role));
            }
        } else if (requirePassword) {
            users.put("admin", new UserInfo("admin", hash(password), "admin"));
        }
        twoFactor = cfg.getBoolean("web-panel.two-factor", false);
        totpSecret = cfg.getString("web-panel.totp-secret", "");
        if (twoFactor && (totpSecret == null || totpSecret.isEmpty())) {
            totpSecret = generateBase32Secret(16);
            plugin.getConfig().set("web-panel.totp-secret", totpSecret);
            plugin.saveConfig();
        }
    }

    public boolean isRunning() { return running; }
    public boolean isDefaultPassword() { return requirePassword && DEFAULT_PASSWORD.equals(password); }
    public String getPanelUrl() { return cachedPanelUrl != null ? cachedPanelUrl : resolvePanelUrl(); }

    private String resolvePanelUrl() {
        String host;
        if (!configuredHost.isEmpty()) {
            host = configuredHost;
        } else if (!"0.0.0.0".equals(bindAddress)) {
            host = bindAddress;
        } else {
            host = detectServerIp();
        }
        return "http://" + host + ":" + port;
    }

    private String detectServerIp() {
        String ip = plugin.getServer().getIp();
        if (ip != null && !ip.isEmpty() && !"0.0.0.0".equals(ip)) return ip;
        ip = fetchPublicIp();
        if (ip != null) return ip;
        ip = getLanIp();
        return ip != null ? ip : "localhost";
    }

    private String fetchPublicIp() {
        if (publicIpUrl == null || publicIpUrl.isEmpty()) return null;
        try {
            java.net.URL url = new java.net.URL(publicIpUrl);
            try (java.io.BufferedReader r = new java.io.BufferedReader(
                    new java.io.InputStreamReader(url.openStream(), StandardCharsets.UTF_8))) {
                String line = r.readLine();
                return (line != null && !line.isBlank()) ? line.trim() : null;
            }
        } catch (Exception e) {
            return null;
        }
    }

    private String getLanIp() {
        try {
            Enumeration<NetworkInterface> nis = NetworkInterface.getNetworkInterfaces();
            while (nis.hasMoreElements()) {
                NetworkInterface ni = nis.nextElement();
                if (ni.isLoopback() || ni.isVirtual() || !ni.isUp()) continue;
                for (Enumeration<InetAddress> ea = ni.getInetAddresses(); ea.hasMoreElements(); ) {
                    InetAddress ia = ea.nextElement();
                    if (ia instanceof Inet4Address && !ia.isLoopbackAddress()) {
                        return ia.getHostAddress();
                    }
                }
            }
        } catch (Exception ignored) {}
        return null;
    }

    // ============================================================
    // Auth
    // ============================================================

    private Map<String, String> parseParams(String query) {
        Map<String, String> m = new LinkedHashMap<>();
        if (query == null || query.isEmpty()) return m;
        for (String pair : query.split("&")) {
            int idx = pair.indexOf('=');
            try {
                if (idx >= 0) {
                    m.put(URLDecoder.decode(pair.substring(0, idx), "UTF-8"),
                            URLDecoder.decode(pair.substring(idx + 1), "UTF-8"));
                } else {
                    m.put(URLDecoder.decode(pair, "UTF-8"), "");
                }
            } catch (Exception ignored) {}
        }
        return m;
    }

    private String readPost(HttpExchange ex) {
        try {
            byte[] b = ex.getRequestBody().readAllBytes();
            return new String(b, StandardCharsets.UTF_8);
        } catch (IOException e) {
            return "";
        }
    }

    private boolean isLocked(String clientIp) {
        Long till = lockUntil.get(clientIp);
        return till != null && till > System.currentTimeMillis();
    }

    private String getSessionToken(HttpExchange ex) {
        if (!requirePassword) return "noauth";
        String cookie = ex.getRequestHeaders().getFirst("Cookie");
        if (cookie == null) return null;
        for (String c : cookie.split(";")) {
            c = c.trim();
            if (c.startsWith("nx_panel=")) {
                String token = c.substring("nx_panel=".length());
                return sessions.containsKey(token) ? token : null;
            }
        }
        return null;
    }

    private String clientIp(HttpExchange ex) {
        List<String> fwd = ex.getRequestHeaders().get("X-Forwarded-For");
        if (fwd != null && !fwd.isEmpty() && !fwd.get(0).isBlank()) {
            return fwd.get(0).split(",")[0].trim();
        }
        return ex.getRemoteAddress() != null ? ex.getRemoteAddress().getAddress().getHostAddress() : "unknown";
    }

    // ============================================================
    // Routing
    // ============================================================

    private void handle(HttpExchange ex) throws IOException {
        try {
            String path = ex.getRequestURI().getPath();
            String method = ex.getRequestMethod();

            if (path.equals("/login")) {
                if (method.equalsIgnoreCase("POST")) { doLogin(ex); return; }
                sendHtml(ex, renderLogin(), "text/html");
                return;
            }
            if (path.equals("/logout")) {
                String tok = getSessionToken(ex);
                if (tok != null) { sessions.remove(tok); sessionRole.remove(tok); }
                sendRedirect(ex, "/login");
                return;
            }

            String token = getSessionToken(ex);
            if (requirePassword && token == null) {
                if (path.startsWith("/api/")) { sendJson(ex, gson.toJson(tree("error", "noauth"))); }
                else sendRedirect(ex, "/login");
                return;
            }

            if (path.equals("/api/metrics")) { sendMetrics(ex); return; }
            if (path.startsWith("/api/")) { handleApi(ex, path); return; }
            if (path.startsWith("/frag/")) { handleFragment(ex, path, token); return; }
            if (path.equals("/events/stream")) { handleSse(ex); return; }
            if (path.equals("/console/stream")) { handleConsoleSse(ex); return; }
            if (path.equals("/action") && method.equalsIgnoreCase("POST")) { handleAction(ex, token); return; }

            // Authenticated pages
            switch (path) {
                case "/", "/dashboard" -> sendHtml(ex, renderDashboard(ex), "text/html");
                case "/players" -> sendHtml(ex, renderPlayers(ex), "text/html");
                case "/player" -> sendHtml(ex, renderPlayerDetail(ex), "text/html");
                case "/events" -> sendHtml(ex, renderEvents(ex), "text/html");
                case "/blacklist" -> sendHtml(ex, renderBlacklist(ex), "text/html");
                case "/audit" -> sendHtml(ex, renderAudit(ex), "text/html");
                case "/suspects" -> sendHtml(ex, renderSuspects(ex), "text/html");
                case "/backups" -> sendHtml(ex, renderBackups(ex), "text/html");
                case "/settings" -> sendHtml(ex, renderSettings(ex), "text/html");
                case "/console" -> sendHtml(ex, renderConsole(ex), "text/html");
                case "/config" -> sendHtml(ex, renderConfig(ex), "text/html");
                default -> sendHtml(ex, page("No encontrado", nav(token) + "<p class='muted'>404</p>", token), "text/html");
            }
        } catch (Exception e) {
            plugin.getLogger().warning("[WebPanel] Error: " + e);
            try { sendHtml(ex, "<h1>Error</h1><pre>" + escapeHtml(e.toString()) + "</pre>", "text/html"); } catch (IOException ignored) {}
        }
    }

    private void handleApi(HttpExchange ex, String path) throws IOException {
        if (path.equals("/api/status")) {
            sendJson(ex, gson.toJson(buildStatusJson()));
        } else if (path.equals("/api/players")) {
        sendJson(ex, gson.toJson(buildPlayersJson()));
    } else if (path.equals("/api/events.csv")) {
        sendCsv(ex, eventsCsv());
    } else if (path.equals("/api/audit.csv")) {
        sendCsv(ex, auditCsv(parseParams(ex.getRequestURI().getQuery())));
    } else {
        sendJson(ex, gson.toJson(tree("error", "unknown")));
    }
}

    private void sendMetrics(HttpExchange ex) throws IOException {
        ex.getResponseHeaders().add("Content-Type", "text/plain; version=0.0.4; charset=utf-8");
        byte[] body = buildMetricsText().getBytes(StandardCharsets.UTF_8);
        ex.sendResponseHeaders(200, body.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(body); }
    }

    private void handleFragment(HttpExchange ex, String path, String token) throws IOException {
        String inner;
        if (path.equals("/frag/dashboard")) inner = dashboardInner();
        else if (path.equals("/frag/players")) inner = playersTable();
        else if (path.equals("/frag/events")) inner = eventsTable(parseParams(ex.getRequestURI().getQuery()));
        else inner = "<p class='muted'>fragmento desconocido</p>";
        sendHtml(ex, inner, "text/html");
    }

    /**
     * Server-Sent Events stream of security alerts (live feed).
     */
    private void handleSse(HttpExchange ex) throws IOException {
        ex.getResponseHeaders().add("Content-Type", "text/event-stream; charset=utf-8");
        ex.getResponseHeaders().add("Cache-Control", "no-cache");
        ex.getResponseHeaders().add("Connection", "keep-alive");
        ex.sendResponseHeaders(200, 0);
        OutputStream os = ex.getResponseBody();
        SseClient client = new SseClient(os);
        sseClients.add(client);
        try {
            client.send(": connected\n\n");
            while (!client.isClosed()) {
                Thread.sleep(15000);
                client.send(": ping\n\n");
            }
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        } catch (Exception ignored) {
        } finally {
            sseClients.remove(client);
            client.close();
        }
    }

    /** Live console stream (server log tail). */
    private void handleConsoleSse(HttpExchange ex) throws IOException {
        ex.getResponseHeaders().add("Content-Type", "text/event-stream; charset=utf-8");
        ex.getResponseHeaders().add("Cache-Control", "no-cache");
        ex.getResponseHeaders().add("Connection", "keep-alive");
        ex.sendResponseHeaders(200, 0);
        OutputStream os = ex.getResponseBody();
        SseClient client = new SseClient(os);
        consoleClients.add(client);
        try {
            for (String l : consoleLines) {
                client.send("data: " + gson.toJson(java.util.Map.of("line", l)) + "\n\n");
            }
            client.send(": connected\n\n");
            while (!client.isClosed()) {
                Thread.sleep(15000);
                client.send(": ping\n\n");
            }
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        } catch (Exception ignored) {
        } finally {
            consoleClients.remove(client);
            client.close();
        }
    }

    /** A single SSE subscriber connection. */
    private static final class SseClient {
        private final OutputStream os;
        private volatile boolean closed = false;
        SseClient(OutputStream os) { this.os = os; }
        void send(String data) {
            if (closed) return;
            try {
                os.write(data.getBytes(StandardCharsets.UTF_8));
                os.flush();
            } catch (IOException e) {
                closed = true;
                try { os.close(); } catch (IOException ignored) {}
            }
        }
        boolean isClosed() { return closed; }
        void close() { closed = true; try { os.close(); } catch (IOException ignored) {} }
    }

    /** Cancels chat for muted players (mute action from the panel). */
    public class WebPanelListener implements Listener {
        @org.bukkit.event.EventHandler
        public void onChat(AsyncPlayerChatEvent e) {
            if (mutedPlayers.contains(e.getPlayer().getUniqueId())) e.setCancelled(true);
        }
    }

    // ============================================================
    // Login
    // ============================================================

    private void doLogin(HttpExchange ex) throws IOException {
        String ip = clientIp(ex);
        Map<String, String> p = parseParams(readPost(ex));
        String userField = p.getOrDefault("username", "admin");
        String pass = p.getOrDefault("password", "");
        String code = p.getOrDefault("code", "");

        if (isLocked(ip)) {
            sendHtml(ex, renderLogin("Demasiados intentos. Bloqueado " + lockoutMinutes + " min."), "text/html");
            return;
        }
        UserInfo user = multiUser ? users.get(userField.toLowerCase()) : users.get("admin");
        if (user == null || !hash(pass).equals(user.hash())) {
            registerFail(ip);
            sendHtml(ex, renderLogin("Credenciales incorrectas."), "text/html");
            return;
        }
        if (twoFactor && !verifyTotp(code)) {
            sendHtml(ex, renderLogin("Código 2FA incorrecto."), "text/html");
            return;
        }
        String token = UUID.randomUUID().toString();
        sessions.put(token, user.name());
        sessionRole.put(token, user.role());
        failedAttempts.remove(ip);
        ex.getResponseHeaders().add("Set-Cookie",
                "nx_panel=" + token + "; Path=/; Max-Age=" + (sessionTimeoutMinutes * 60) + "; HttpOnly; SameSite=Lax");
        sendRedirect(ex, "/dashboard");
    }

    private void registerFail(String ip) {
        int tries = failedAttempts.merge(ip, 1, Integer::sum);
        if (tries >= maxFailedLogins) {
            lockUntil.put(ip, System.currentTimeMillis() + lockoutMinutes * 60_000L);
            failedAttempts.remove(ip);
        }
    }

    private String getRole(String token) {
        if (token == null) return "viewer";
        if (!requirePassword) return "admin";
        return sessionRole.getOrDefault(token, "viewer");
    }

    private String renderLogin() { return renderLogin(null); }

    private String renderLogin(String error) {
        return "<!doctype html><html lang='es'><head><meta charset='utf-8'>" +
                "<meta name='viewport' content='width=device-width,initial-scale=1'>" +
                "<title>NexusSecurity — Acceso</title>" + style() + "</head><body>" +
                "<div class='login'><div class='brand'>NexusSecurity</div>" +
                "<h2>Panel de Administración</h2>" +
                (error != null ? "<div class='msg err'>" + escapeHtml(error) + "</div>" : "") +
                (isDefaultPassword() ? "<div class='msg warn'>Usando contraseña por defecto: <b>" + DEFAULT_PASSWORD + "</b>. Cámbiala en config.yml.</div>" : "") +
                "<form method='post' action='/login'>" +
                (multiUser ? "<input type='text' name='username' placeholder='Usuario' autofocus>" : "") +
                "<input type='password' name='password' placeholder='Contraseña'" + (multiUser ? "" : " autofocus") + ">" +
                (twoFactor ? "<input type='text' name='code' placeholder='Código 2FA' inputmode='numeric'>" : "") +
                "<button type='submit'>Entrar</button></form>" +
                "<p class='muted'>Versión " + plugin.getDescription().getVersion() + "</p></div></body></html>";
    }

    // ============================================================
    // Pages
    // ============================================================

    private String nav(String token) {
        boolean premium = plugin.getSubscriptionManager().isSubscriptionActive();
        String planBadge = premium
                ? "<span class='plan premium'>★ PREMIUM</span>"
                : "<span class='plan free'>GRATUITA</span>";
        return "<nav><a href='/dashboard'>Dashboard</a><a href='/players'>Jugadores</a>" +
                "<a href='/suspects'>Sospechosos</a><a href='/blacklist'>Blacklist IP</a>" +
                "<a href='/backups'>Backups</a><a href='/audit'>Auditoría</a><a href='/events'>Eventos</a>" +
                "<a href='/settings'>Ajustes</a><a href='/console'>Consola</a><a href='/config'>Config</a>" +
                "<span class='right'>" + planBadge + "</span>" +
                "<a class='right' href='javascript:toggleTheme()' title='Cambiar tema'>Tema</a>" +
                "<a class='right' href='/logout'>Salir</a></nav>";
    }

    private String page(String title, String body, String token) {
        return "<!doctype html><html lang='es'><head><meta charset='utf-8'>" +
                "<meta name='viewport' content='width=device-width,initial-scale=1'>" +
                "<title>NexusSecurity — " + escapeHtml(title) + "</title>" + style() +
                "</head><body>" + nav(token) + "<div class='wrap'>" + body + "</div>" +
                "<footer class='muted'>NexusSecurity " + plugin.getDescription().getVersion() + " · Panel embebido</footer>" +
                "<script>function toggleTheme(){var l=document.body.classList.toggle('light');" +
                "document.cookie='nx_theme='+(l?'light':'dark')+';Path=/;Max-Age=31536000';}" +
                "try{var t=document.cookie.match(/nx_theme=(light|dark)/);if(t&&t[1]==='light')document.body.classList.add('light');}catch(e){}" +
                "</script></body></html>";
    }

    private String renderDashboard(HttpExchange ex) {
        String token = getSessionToken(ex);
        String body = "<div class='live' id='live'>" + dashboardInner() + "</div>" +
                liveScript("dashboard");
        return page("Dashboard", body, token);
    }

    private String dashboardInner() {
        var pm = plugin.getPerformanceMonitor();
        var mm = plugin.getModuleManager();
        var sub = plugin.getSubscriptionManager();

        StringBuilder b = new StringBuilder();
        b.append("<header class='page'><h1>Dashboard</h1>");
        b.append("<span class='ts' id='ts'>").append(Instant.now().atZone(ZoneId.systemDefault())
                .format(DateTimeFormatter.ofPattern("HH:mm:ss"))).append("</span></header>");

        if (!sub.isSubscriptionActive()) {
            b.append("<div class='upsell'>Estás en la <b>Versión Gratuita</b>. Las acciones (módulos, escaneos, jugadores, blacklist) requieren suscripción.<br>" +
                    "Activa <b>PREMIUM</b> con tu API key para desbloquear el panel de control completo, gestión de jugadores y auditoría en vivo.</div>");
        } else {
            String plan = "PREMIUM";
            String expires = "";
            try {
                var s = plugin.getSubscriptionManager().getCurrentSubscription();
                if (s != null) {
                    plan = s.getPlan() != null ? s.getPlan() : plan;
                    if (s.getExpiresAt() > 0) {
                        expires = " · Expira: " + fmtTime(s.getExpiresAt());
                    }
                }
            } catch (Exception ignored) {}
            b.append("<div class='premiumok'>★ <b>").append(escapeHtml(plan)).append("</b> ACTIVO").append(escapeHtml(expires)).append(" — Funciones completas habilitadas</div>");
        }

        // Stats + charts
        b.append("<div class='cards'>");
        b.append(statCard("TPS", String.format("%.1f", pm.getCurrentTps()), pm.isTpsLow() ? "bad" : "ok",
                sparkline(pm.getTpsHistory(), "#4ade80", 0, 20)));
        b.append(statCard("CPU", String.format("%.1f%%", pm.getCpuUsagePercent()), "ok",
                sparkline(pm.getCpuHistory(), "#fbbf24", 0, 100)));
        b.append(statCard("RAM", pm.getUsedRamMb() + "MB / " + pm.getTotalRamMb() + "MB",
                pm.getUsedRamMb() > pm.getTotalRamMb() * 0.85 ? "bad" : "ok",
                sparkline(toDouble(pm.getRamHistory()), "#60a5fa", 0, Math.max(pm.getTotalRamMb(), 1))));
        b.append(statCard("Módulos", mm.getActiveModuleCount() + "/" + mm.getTotalModuleCount(), "ok", ""));
        b.append("</div>");

        // Server info
        Map<String, Object> ss = collectServerStats();
        b.append("<div class='card'><h3>Servidor</h3><div class='kv'>");
        b.append(kv("Uptime", fmtUptime(toLong(ss.get("uptime")))));
        b.append(kv("Java", escapeHtml(String.valueOf(ss.get("javaVersion")))));
        b.append(kv("SO", escapeHtml(String.valueOf(ss.get("os")))));
        b.append(kv("Núcleos", String.valueOf(ss.get("cores"))));
        b.append(kv("Mundos", String.valueOf(ss.get("worlds"))));
        b.append(kv("Entidades", String.valueOf(ss.get("entities"))));
        b.append(kv("Chunks", String.valueOf(ss.get("chunks"))));
        b.append(kv("Jugadores online", String.valueOf(ss.get("players"))));
        b.append(kv("Disco usado", fmtMB(toLong(ss.get("diskUsed"))) + " / " + fmtMB(toLong(ss.get("diskTotal")))));
        b.append("</div>");
        int health = toInt(ss.get("health"));
        b.append("<div class='health'>Salud del servidor: <b>").append(health).append("%</b> ")
                .append("<div class='bar' style='width:").append(health).append("%;background:")
                .append(health > 70 ? "#4ade80" : health > 40 ? "#fbbf24" : "#f87171").append("'></div></div>");
        b.append("</div>");

        // Emergency mode
        Autopilot autopilot = plugin.getModuleManager().getModule("autopilot", Autopilot.class);
        boolean emerg = autopilot != null && autopilot.getEmergencyMode() != null && autopilot.getEmergencyMode().isActive();
        b.append("<div class='card'><h3>Modo de Emergencia</h3>");
        if (emerg) {
            b.append("<div class='banner'>EMERGENCIA ACTIVA</div>");
            b.append(actionForm("emergency", "Desactivar emergencia", "btn warn", Map.of("state", "off")));
        } else {
            if (sub.isSubscriptionActive()) {
                b.append(actionForm("emergency", "Activar emergencia", "btn danger", Map.of("state", "on")));
            } else {
                b.append("<p class='muted'>Requiere suscripción activa.</p>");
            }
        }
        b.append("</div>");

        // Modules
        b.append("<div class='card'><h3>Módulos</h3><table class='grid'>");
        b.append("<tr><th>Módulo</th><th>Estado</th><th>Acción</th></tr>");
        for (SecurityModule m : mm.getAllModules().values()) {
            boolean active = mm.isModuleActive(normalize(m.getName()));
            String color = active ? "ok" : "muted";
            b.append("<tr><td>").append(escapeHtml(m.getName())).append("</td>");
            b.append("<td><span class='dot ").append(color).append("'></span>").append(active ? "Activo" : "Inactivo").append("</td>");
            if (sub.isSubscriptionActive()) {
                String cell = active
                        ? actionForm("disable", "Desactivar", "btn small", Map.of("module", m.getName()))
                        : actionForm("enable", "Activar", "btn small ok", Map.of("module", m.getName()));
                b.append("<td>").append(cell).append("</td>");
            } else {
                b.append("<td class='muted'>-</td>");
            }
            b.append("</tr>");
        }
        b.append("</table></div>");

        // Module resource scores
        b.append("<div class='card'><h3>Score de recursos por módulo</h3><table class='grid'>");
        b.append("<tr><th>Módulo</th><th>Score</th><th>Barra</th></tr>");
        for (SecurityModule m : mm.getAllModules().values()) {
            double score = m.getResourceUsageScore();
            int pct = (int) (score * 100);
            String color = score > 0.7 ? "#f87171" : score > 0.4 ? "#fbbf24" : "#4ade80";
            b.append("<tr><td>").append(escapeHtml(m.getName())).append("</td>");
            b.append("<td>").append(String.format("%.2f", score)).append("</td>");
            b.append("<td><div class='bar' style='width:").append(pct).append("%;background:").append(color).append("'></div></td></tr>");
        }
        b.append("</table></div>");

        // Quick actions
        if (sub.isSubscriptionActive()) {
            b.append("<div class='card'><h3>Acciones rápidas</h3><div class='row'>");
            b.append(actionForm("scan", "Escanear (Guardian)", "btn", Map.of()));
            b.append(actionForm("backup", "Backup (Vault)", "btn", Map.of()));
            b.append("</div></div>");
        }
        return b.toString();
    }

    private String renderPlayers(HttpExchange ex) {
        String token = getSessionToken(ex);
        String body = "<header class='page'><h1>Jugadores</h1>" +
                "<span class='ts' id='ts'></span></header>" +
                "<div class='live' id='live'>" + playersTable() + "</div>" + liveScript("players");
        return page("Jugadores", body, token);
    }

    private String playersTable() {
        final List<Player> players = collectOnlinePlayers();
        StringBuilder b = new StringBuilder();
        b.append("<div class='card'><p class='muted'>").append(players.size()).append(" en línea</p><table class='grid'>");
        b.append("<tr><th>Avatar</th><th>Nombre</th><th>UUID</th><th>IP</th><th>Ping</th><th>Op</th><th></th></tr>");
        for (Player p : players) {
            b.append("<tr><td><img class='avatar' src='https://mc-heads.net/avatar/").append(p.getUniqueId()).append("/24' alt=''></td>");
            b.append("<td>").append(escapeHtml(p.getName())).append("</td>");
            b.append("<td class='mono small'>").append(p.getUniqueId()).append("</td>");
            b.append("<td>").append(escapeHtml(p.getAddress() != null ? p.getAddress().getAddress().getHostAddress() : "?")).append("</td>");
            b.append("<td>").append(p.getPing()).append("ms</td>");
            b.append("<td>").append(p.isOp() ? "<span class='dot ok'></span>" : "<span class='dot bad'></span>").append("</td>");
            b.append("<td><a class='btn small' href='/player?uuid=").append(p.getUniqueId()).append("'>Ver</a></td></tr>");
        }
        b.append("</table></div>");
        return b.toString();
    }

    private String renderPlayerDetail(HttpExchange ex) throws IOException {
        String token = getSessionToken(ex);
        Map<String, String> q = parseParams(ex.getRequestURI().getQuery());
        String uuid = q.get("uuid");
        if (uuid == null || uuid.isEmpty()) return page("Jugador", nav(token) + "<p class='muted'>Sin UUID</p>", token);

        PlayerDetail d = getPlayerDetail(UUID.fromString(uuid));
        if (d == null) return page("Jugador", nav(token) + "<p class='muted'>No encontrado / offline</p>", token);

        var sub = plugin.getSubscriptionManager();
        StringBuilder b = new StringBuilder();
        b.append("<header class='page'><h1><img class='avatar' src='https://mc-heads.net/avatar/")
                .append(uuid).append("/32'> ").append(escapeHtml(d.name())).append("</h1></header>");
        b.append("<div class='cards'>");
        b.append(statCard("UUID", "<span class='mono small'>" + uuid + "</span>", "muted", ""));
        b.append(statCard("IP", escapeHtml(d.ip()), "ok", ""));
        b.append(statCard("Ping", d.ping() + "ms", "ok", ""));
        b.append(statCard("Modo", d.gamemode(), "ok", ""));
        b.append(statCard("Mundo", escapeHtml(d.world()), "ok", ""));
        b.append(statCard("Vida", String.format("%.0f", d.health()), d.health() < 6 ? "bad" : "ok", ""));
        b.append(statCard("Comida", String.valueOf(d.food()), d.food() < 6 ? "bad" : "ok", ""));
        b.append(statCard("Nivel", String.valueOf(d.level()), "ok", ""));
        b.append("</div>");

        b.append("<div class='card'><h3>Estado</h3><p>");
        b.append("OP: ").append(d.op() ? "Sí" : "No").append(" · ");
        b.append("Bypass: ").append(d.bypass() ? "Sí" : "No").append(" · ");
        b.append("Volando: ").append(d.flying() ? "Sí" : "No").append(" · ");
        b.append("Baneado: ").append(d.banned() ? "Sí" : "No").append("<br>");
        b.append("IP baneada (rate-limit): ").append(d.ipBanned() ? "Sí" : "No").append(" · ");
        boolean frozen = frozenPlayers.contains(java.util.UUID.fromString(uuid));
        boolean muted = mutedPlayers.contains(java.util.UUID.fromString(uuid));
        b.append("Congelado: ").append(frozen ? "Sí" : "No").append(" · ");
        b.append("Silenciado: ").append(muted ? "Sí" : "No").append("<br>");
        b.append("Violaciones HackDetector: ").append(d.violations()).append("</p>");
        if (!d.effects().isEmpty()) b.append("<p class='muted'>Efectos: ").append(escapeHtml(String.join(", ", d.effects()))).append("</p>");
        b.append("</div>");

        if (sub.isSubscriptionActive()) {
            b.append("<div class='card'><h3>Acciones</h3><div class='row'>");
            b.append(actionForm("kick", "Expulsar", "btn", Map.of("uuid", uuid, "name", d.name())));
            b.append(actionForm("warn", "Avisar", "btn warn", Map.of("uuid", uuid, "name", d.name())));
            b.append(actionForm(frozen ? "unfreeze" : "freeze", frozen ? "Descongelar" : "Congelar", "btn", Map.of("uuid", uuid, "name", d.name())));
            b.append(actionForm(muted ? "unmute" : "mute", muted ? "Quitar silencio" : "Silenciar", "btn", Map.of("uuid", uuid, "name", d.name())));
            b.append("</div>");
            b.append("<form method='post' action='/action' class='row'>");
            b.append(hidden("action", "tempban")).append(hidden("uuid", uuid)).append(hidden("name", d.name()));
            b.append("<input name='hours' type='number' min='1' value='24' title='Horas' style='width:90px'>");
            b.append("<button class='btn danger'>Ban temporal</button></form>");
            b.append("<form method='post' action='/action' class='row'>");
            b.append(hidden("action", "ban")).append(hidden("uuid", uuid)).append(hidden("name", d.name()));
            b.append("<input name='reason' placeholder='Motivo (opcional)'>");
            b.append("<button class='btn danger'>Ban permanente</button></form>");
            b.append("</div>");
        } else {
            b.append("<div class='card'><p class='muted'>Acciones sobre jugadores requieren suscripción activa.</p></div>");
        }
        // Violation history
        b.append("<div class='card'><h3>Historial de violaciones</h3><table class='grid'>");
        b.append("<tr><th>Tipo</th><th>Conteo</th><th>Última</th><th>Detalles</th></tr>");
        for (Map<String, Object> v : plugin.getDatabaseManager().queryViolations(java.util.UUID.fromString(uuid))) {
            b.append("<tr><td>").append(escapeHtml(String.valueOf(v.get("violation_type")))).append("</td>");
            b.append("<td>").append(String.valueOf(v.get("violation_count"))).append("</td>");
            b.append("<td class='mono small'>").append(escapeHtml(fmtTime(toLong(v.get("last_violation"))))).append("</td>");
            b.append("<td>").append(escapeHtml(String.valueOf(v.get("details")))).append("</td></tr>");
        }
        b.append("</table></div>");
        return page("Jugador", b.toString(), token);
    }

    private String renderEvents(HttpExchange ex) {
        String token = getSessionToken(ex);
        Map<String, String> q = parseParams(ex.getRequestURI().getQuery());
        StringBuilder b = new StringBuilder();
        b.append("<header class='page'><h1>Eventos de Seguridad</h1>");
        b.append("<a class='btn small' href='/api/events.csv'>Exportar CSV</a></header>");
        b.append("<form method='get' action='/events' class='row'><select name='module'>");
        String sel = q.getOrDefault("module", "");
        b.append("<option value=''>Todos los módulos</option>");
        for (String mod : moduleNames()) {
            b.append("<option value='").append(mod).append("'").append(mod.equals(sel) ? " selected" : "").append(">")
                    .append(escapeHtml(mod)).append("</option>");
        }
        b.append("</select><button class='btn small'>Filtrar</button></form>");
        b.append("<div class='live' id='live'>").append(eventsTable(q)).append("</div>");
        b.append("<script>" +
                "var nx_es = ('EventSource' in window) ? new EventSource('/events/stream') : null;" +
                "function nx_addRow(d){var t=document.querySelector('#live table tbody'); if(!t) return;" +
                "var sev=(d.severity||'').toLowerCase(); var cls=sev==='critical'||sev==='error'?'bad':sev==='warning'?'warn':'ok';" +
                "var tr=document.createElement('tr');" +
                "tr.innerHTML='<td class=\"mono small\">'+new Date(d.timestamp).toLocaleString()+'</td>'+'" +
                "'<td><span class=\"dot '+cls+'\"></span>'+(d.severity||'')+'</td>'+'" +
                "'<td>'+(d.module||'')+'</td><td>'+(d.message||'')+'</td><td class=\"mono small\">'+(d.source||'—')+'</td>';" +
                "t.insertBefore(tr, t.firstChild);" +
                "while(t.children.length>200) t.removeChild(t.lastChild);}" +
                "if(nx_es){nx_es.onmessage=function(e){try{var d=JSON.parse(e.data); nx_addRow(d);" +
                "if((d.severity||'').toLowerCase()==='critical'){nx_toast('ALERTA: '+ (d.module||'')+': '+(d.message||''));}}catch(_){}};" +
                "nx_es.onerror=function(){nx_es.close(); nx_es=null;};}" +
                "if(!nx_es){setInterval(function(){fetch('/frag/events').then(r=>r.text()).then(h=>{var el=document.getElementById('live'); if(el) el.innerHTML=h;}).catch(function(){});},10000);}" +
                "function nx_toast(msg){try{var t=document.createElement('div'); t.className='toast'; t.textContent=msg;" +
                "document.body.appendChild(t); setTimeout(function(){t.remove();},6000);}catch(_){}}" +
                "</script>");
        return page("Eventos", b.toString(), token);
    }

    private String eventsTable(Map<String, String> q) {
        String filter = q != null ? q.getOrDefault("module", "") : "";
        var events = plugin.getAlertSystem().getRecentEvents();
        StringBuilder b = new StringBuilder();
        b.append("<div class='card'><table class='grid'>");
        b.append("<tr><th>Hora</th><th>Gravedad</th><th>Módulo</th><th>Mensaje</th><th>IP</th></tr>");
        int shown = 0;
        for (AlertSystem.AlertEntry e : events) {
            if (!filter.isEmpty() && !filter.equalsIgnoreCase(e.module())) continue;
            b.append("<tr><td class='mono small'>").append(escapeHtml(fmtTime(e.timestamp()))).append("</td>");
            b.append("<td>").append(severityBadge(e.severity())).append("</td>");
            b.append("<td>").append(escapeHtml(e.module())).append("</td>");
            b.append("<td>").append(escapeHtml(e.description())).append("</td>");
            b.append("<td class='mono small'>").append(escapeHtml(e.source() != null ? e.source() : "—")).append("</td></tr>");
            if (++shown >= 200) break;
        }
        if (shown == 0) b.append("<tr><td colspan='5' class='muted'>Sin eventos.</td></tr>");
        b.append("</table></div>");
        return b.toString();
    }

    private String renderBlacklist(HttpExchange ex) {
        String token = getSessionToken(ex);
        var sub = plugin.getSubscriptionManager();
        StringBuilder b = new StringBuilder();
        b.append("<header class='page'><h1>Blacklist de IP</h1></header>");
        b.append("<div class='card'><h3>Añadir IP</h3>");
        if (sub.isSubscriptionActive()) {
            b.append("<form method='post' action='/action' class='row'>");
            b.append(hidden("action", "add-ip"));
            b.append("<input name='ip' placeholder='1.2.3.4' required>");
            b.append("<input name='reason' placeholder='Motivo'>");
            b.append("<input name='score' type='number' value='90' title='Threat score' style='width:80px'>");
            b.append("<button class='btn danger'>Añadir</button></form>");
        } else {
            b.append("<p class='muted'>Requiere suscripción activa.</p>");
        }
        b.append("</div>");

        b.append("<div class='card'><h3>IPs bloqueadas</h3><table class='grid'>");
        b.append("<tr><th>IP</th><th>Motivo</th><th>Origen</th><th>Score</th><th></th></tr>");
        for (Map<String, Object> row : plugin.getDatabaseManager().listBlacklist(200)) {
            String ip = String.valueOf(row.get("ip_address"));
            b.append("<tr><td class='mono small'>").append(escapeHtml(ip)).append("</td>");
            b.append("<td>").append(escapeHtml(String.valueOf(row.get("reason")))).append("</td>");
            b.append("<td>").append(escapeHtml(String.valueOf(row.get("source")))).append("</td>");
            b.append("<td>").append(String.valueOf(row.get("threat_score"))).append("</td>");
            if (sub.isSubscriptionActive()) {
                b.append("<td>").append(actionForm("unban-ip", "Quitar", "btn small", Map.of("ip", ip))).append("</td>");
            } else {
                b.append("<td class='muted'>-</td>");
            }
            b.append("</tr>");
        }
        b.append("</table></div>");
        return page("Blacklist", b.toString(), token);
    }

    private String renderAudit(HttpExchange ex) {
        String token = getSessionToken(ex);
        Map<String, String> q = parseParams(ex.getRequestURI().getQuery());
        String actor = q.getOrDefault("actor", "");
        String action = q.getOrDefault("action", "");
        String search = q.getOrDefault("q", "");
        int page = parseIntSafe(q.get("page"), 0);
        int size = 50;
        int offset = page * size;

        StringBuilder b = new StringBuilder();
        b.append("<header class='page'><h1>Auditoría</h1>");
        b.append("<a class='btn small' href='/api/audit.csv?actor=").append(escapeHtml(actor))
                .append("&action=").append(escapeHtml(action)).append("&q=").append(escapeHtml(search)).append("'>Exportar CSV</a></header>");
        b.append("<form method='get' action='/audit' class='row'>");
        b.append("<input name='actor' value='").append(escapeHtml(actor)).append("' placeholder='Actor'>");
        b.append("<input name='action' value='").append(escapeHtml(action)).append("' placeholder='Acción'>");
        b.append("<input name='q' value='").append(escapeHtml(search)).append("' placeholder='Buscar...'>");
        b.append("<button class='btn small'>Filtrar</button></form>");

        b.append("<div class='card'><table class='grid'>");
        b.append("<tr><th>Hora</th><th>Actor</th><th>Acción</th><th>Objetivo</th><th>Resultado</th></tr>");
        java.text.SimpleDateFormat fmt = new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        List<Map<String, Object>> rows = plugin.getDatabaseManager().queryAuditLog(actor, action, search, -1, -1, size, offset);
        for (Map<String, Object> row : rows) {
            long ts = toLong(row.get("timestamp"));
            b.append("<tr><td class='mono small'>").append(ts > 0 ? fmt.format(new java.util.Date(ts)) : "—").append("</td>");
            b.append("<td>").append(escapeHtml(String.valueOf(row.get("actor")))).append("</td>");
            b.append("<td>").append(escapeHtml(String.valueOf(row.get("action")))).append("</td>");
            b.append("<td>").append(escapeHtml(String.valueOf(row.get("target")))).append("</td>");
            b.append("<td>").append(escapeHtml(String.valueOf(row.get("result")))).append("</td></tr>");
        }
        if (rows.isEmpty()) b.append("<tr><td colspan='5' class='muted'>Sin registros.</td></tr>");
        b.append("</table></div>");

        b.append("<div class='row'>");
        if (page > 0) {
            b.append("<a class='btn small' href='/audit?actor=").append(escapeHtml(actor)).append("&action=").append(escapeHtml(action))
                    .append("&q=").append(escapeHtml(search)).append("&page=").append(page - 1).append("'>← Anterior</a>");
        }
        if (rows.size() == size) {
            b.append("<a class='btn small' href='/audit?actor=").append(escapeHtml(actor)).append("&action=").append(escapeHtml(action))
                    .append("&q=").append(escapeHtml(search)).append("&page=").append(page + 1).append("'>Siguiente →</a>");
        }
        b.append("</div>");
        return page("Auditoría", b.toString(), token);
    }

    private String renderSuspects(HttpExchange ex) {
        String token = getSessionToken(ex);
        HackDetector hd = plugin.getModuleManager().getModule("hackdetector", HackDetector.class);
        StringBuilder b = new StringBuilder();
        b.append("<header class='page'><h1>Sospechosos (HackDetector)</h1></header>");
        if (hd == null || !hd.isEnabled()) {
            b.append("<div class='card'><p class='muted'>HackDetector no está activo.</p></div>");
            return page("Sospechosos", b.toString(), token);
        }
        Map<UUID, Integer> counts = hd.getActiveViolationCounts();
        b.append("<div class='card'><p class='muted'>").append(counts.size()).append(" con violaciones activas</p><table class='grid'>");
        b.append("<tr><th>Jugador</th><th>UUID</th><th>Violaciones</th><th></th></tr>");
        for (Map.Entry<UUID, Integer> e : counts.entrySet()) {
            OfflinePlayer op = Bukkit.getOfflinePlayer(e.getKey());
            String name = op != null && op.getName() != null ? op.getName() : e.getKey().toString();
            b.append("<tr><td>").append(escapeHtml(name)).append("</td>");
            b.append("<td class='mono small'>").append(e.getKey()).append("</td>");
            b.append("<td>").append(e.getValue()).append("</td>");
            b.append("<td><a class='btn small' href='/player?uuid=").append(e.getKey()).append("'>Ver</a></td></tr>");
        }
        b.append("</table></div>");
        return page("Sospechosos", b.toString(), token);
    }

    private String renderSettings(HttpExchange ex) {
        String token = getSessionToken(ex);
        String user = sessions.get(token);
        StringBuilder b = new StringBuilder();
        b.append("<header class='page'><h1>Ajustes del panel</h1></header>");
        Map<String, String> q = parseParams(ex.getRequestURI().getQuery());
        if ("1".equals(q.get("ok"))) b.append("<div class='premiumok'>Contraseña actualizada correctamente.</div>");
        if ("1".equals(q.get("e"))) b.append("<div class='banner'>Contraseña actual incorrecta.</div>");

        b.append("<div class='card'><h3>Usuario</h3><p>Conectado como <b>").append(escapeHtml(user != null ? user : "admin"))
                .append("</b> · Rol: ").append(escapeHtml(getRole(token))).append("</p></div>");

        b.append("<div class='card'><h3>Cambiar contraseña</h3><form method='post' action='/action' class='col'>");
        b.append(hidden("action", "change-password"));
        b.append("<input type='password' name='current' placeholder='Contraseña actual' required>");
        b.append("<input type='password' name='new' placeholder='Nueva contraseña' required>");
        b.append("<button class='btn'>Guardar</button></form></div>");

        if (twoFactor && totpSecret != null && !totpSecret.isEmpty()) {
            String label = "NexusSecurity:" + (user != null ? user : "admin");
            String otpauth = "otpauth://totp/" + escapeHtml(label) + "?secret=" + totpSecret + "&issuer=NexusSecurity";
            b.append("<div class='card'><h3>2FA (TOTP)</h3>");
            b.append("<p class='muted'>Escanea este código en Google Authenticator / Authy:</p>");
            b.append("<p class='mono'>").append(escapeHtml(totpSecret)).append("</p>");
            b.append("<p class='muted small'>").append(escapeHtml(otpauth)).append("</p></div>");
        }
        return page("Ajustes", b.toString(), token);
    }

    private String renderConsole(HttpExchange ex) {
        String token = getSessionToken(ex);
        Map<String, String> q = parseParams(ex.getRequestURI().getQuery());
        StringBuilder b = new StringBuilder();
        b.append("<header class='page'><h1>Consola del servidor</h1>");
        if ("1".equals(q.get("ok"))) b.append("<div class='premiumok'>Comando enviado.</div>");
        b.append("</header>");
        b.append("<div class='card'><form method='post' action='/action' class='col'>");
        b.append(hidden("action", "run-command"));
        b.append("<input type='text' name='command' placeholder='Ej. ban Notch hacks' autofocus>");
        b.append("<button class='btn'>Ejecutar</button></form>");
        b.append("<p class='muted small'>Se ejecuta como consola del servidor (rol admin). Usa con cuidado.</p></div>");
        b.append("<div class='card'><pre id='console' class='console'></pre></div>");
        b.append("<script>");

        b.append("var es = new EventSource('/console/stream');");
        b.append("var box = document.getElementById('console');");
        b.append("es.onmessage = function(e){ try { var o = JSON.parse(e.data); if (o.line) {");
        b.append("box.textContent += o.line + '\\n'; box.scrollTop = box.scrollHeight;");
        b.append("} } catch(_){} };");
        b.append("es.onerror = function(){ setTimeout(function(){ location.reload(); }, 5000); };");
        b.append("</script>");
        return page("Consola", b.toString(), token);
    }

    private String renderConfig(HttpExchange ex) {
        String token = getSessionToken(ex);
        Map<String, String> q = parseParams(ex.getRequestURI().getQuery());
        StringBuilder b = new StringBuilder();
        b.append("<header class='page'><h1>Configuración (config.yml)</h1>");
        if ("1".equals(q.get("ok"))) b.append("<div class='premiumok'>Guardado. Algunos módulos pueden requerir /security reload.</div>");
        b.append("</header>");
        b.append("<div class='card'><form method='post' action='/action' class='col'>");
        b.append(hidden("action", "save-config"));
        String content = "";
        try {
            java.io.File cfgFile = new java.io.File(plugin.getDataFolder(), "config.yml");
            content = java.nio.file.Files.readString(cfgFile.toPath(), StandardCharsets.UTF_8);
        } catch (Exception e) {
            content = "# No se pudo leer config.yml: " + escapeHtml(e.getMessage());
        }
        b.append("<textarea name='yaml' rows='28'>").append(escapeHtml(content)).append("</textarea>");
        b.append("<button class='btn'>Guardar y recargar</button></form>");
        b.append("<p class='muted small'>Editar aquí equivale a editar config.yml. Se recarga la config del plugin automáticamente.</p></div>");
        return page("Config", b.toString(), token);
    }

    private String renderBackups(HttpExchange ex) {
        String token = getSessionToken(ex);
        StringBuilder b = new StringBuilder();
        b.append("<header class='page'><h1>Backups (Vault)</h1>");
        b.append(actionForm("backup", "Nuevo backup", "btn small", Map.of())).append("</header>");
        if (!plugin.getSubscriptionManager().isSubscriptionActive()) {
            b.append("<div class='upsell'>La gestión de backups requiere suscripción activa.</div>");
            return page("Backups", b.toString(), token);
        }
        Vault v = plugin.getModuleManager().getModule("vault", Vault.class);
        if (v == null || v.getBackupScheduler() == null) {
            b.append("<p class='muted'>Vault no disponible.</p>");
            return page("Backups", b.toString(), token);
        }
        b.append("<div class='card'><table class='grid'>");
        b.append("<tr><th>Archivo</th><th>Tipo</th><th>Tamaño</th><th>Fecha</th><th></th></tr>");
        for (Map<String, Object> row : v.getBackupScheduler().listBackupDetails()) {
            String name = String.valueOf(row.get("name"));
            long size = toLong(row.get("size"));
            long modified = toLong(row.get("modified"));
            b.append("<tr><td class='mono small'>").append(escapeHtml(name)).append("</td>");
            b.append("<td>").append(escapeHtml(String.valueOf(row.get("type")))).append("</td>");
            b.append("<td>").append(size / (1024 * 1024)).append(" MB</td>");
            b.append("<td class='mono small'>").append(escapeHtml(fmtTime(modified))).append("</td>");
            b.append("<td>").append(actionForm("restore-backup", "Restaurar", "btn danger small", Map.of("file", name))).append("</td></tr>");
        }
        b.append("</table></div>");
        return page("Backups", b.toString(), token);
    }

    // ============================================================
    // Actions
    // ============================================================

    private void handleAction(HttpExchange ex, String token) throws IOException {
        Map<String, String> p = parseParams(readPost(ex));
        String action = p.get("action");
        var sub = plugin.getSubscriptionManager();
        String clientIp = clientIp(ex);

        boolean needsSub = action != null && Set.of("enable", "disable", "scan", "backup",
                "kick", "ban", "tempban", "warn", "add-ip", "unban-ip", "emergency",
                "restore-backup", "freeze", "unfreeze", "mute", "unmute",
                "run-command", "save-config").contains(action);

        if (needsSub && !sub.isSubscriptionActive()) {
            sendHtml(ex, page("Bloqueado", nav(token) + "<div class='banner'>Esta función requiere una suscripción activa.</div>", token), "text/html");
            return;
        }
        if (!"admin".equals(getRole(token))) {
            sendHtml(ex, page("Bloqueado", nav(token) + "<div class='banner'>Tu rol (viewer) no permite realizar acciones. Contacta al administrador.</div>", token), "text/html");
            return;
        }

        switch (action) {
            case "enable" -> { plugin.getModuleManager().enableModule(normalize(p.get("module"))); plugin.logAction("WebPanel", "enable:" + p.get("module"), p.get("module"), "ok"); }
            case "disable" -> { plugin.getModuleManager().disableModule(normalize(p.get("module"))); plugin.logAction("WebPanel", "disable:" + p.get("module"), p.get("module"), "ok"); }
            case "scan" -> { Guardian g = plugin.getModuleManager().getModule("guardian", Guardian.class); if (g != null) g.runScan(); plugin.logAction("WebPanel", "scan", "guardian", "ok"); }
            case "backup" -> { Vault v = plugin.getModuleManager().getModule("vault", Vault.class); if (v != null && v.getBackupScheduler() != null) v.getBackupScheduler().performBackupNow(); plugin.logAction("WebPanel", "backup", "vault", "ok"); }
            case "emergency" -> toggleEmergency("on".equals(p.get("state")));
            case "kick" -> playerAction(p.get("uuid"), p.get("name"),
                    (pl) -> pl.kick(net.kyori.adventure.text.Component.text("Expulsado por el panel web de NexusSecurity.")),
                    "kick", p);
            case "warn" -> { plugin.getAlertSystem().warning("WebPanel", "PlayerAction", "Aviso a " + p.get("name") + ": " + p.getOrDefault("reason", "—")); plugin.logAction("WebPanel", "warn", p.get("name"), "ok"); }
            case "ban" -> playerAction(p.get("uuid"), p.get("name"),
                    (pl) -> Bukkit.getBanList(BanList.Type.NAME).addBan(p.get("name"), p.getOrDefault("reason", "Baneado por NexusSecurity"), null, "NexusSecurity-Web"),
                    "ban", p);
            case "tempban" -> {
                int hours = parseIntSafe(p.get("hours"), 24);
                long exp = System.currentTimeMillis() + hours * 3600_000L;
                Date d = new Date(exp);
                playerAction(p.get("uuid"), p.get("name"),
                        (pl) -> Bukkit.getBanList(BanList.Type.NAME).addBan(p.get("name"), "Ban temporal (" + hours + "h) por NexusSecurity", d, "NexusSecurity-Web"),
                        "tempban", p);
            }
            case "add-ip" -> {
                String ip = p.get("ip"); int score = parseIntSafe(p.get("score"), 90);
                plugin.getDatabaseManager().blacklistIp(ip, p.getOrDefault("reason", "Añadido desde panel"), "WebPanel", -1, score);
                plugin.getLogger().info("[WebPanel] IP añadida a blacklist: " + ip);
            }
            case "unban-ip" -> {
                String ip = p.get("ip");
                boolean ok = plugin.getDatabaseManager().removeFromBlacklist(ip);
                plugin.getLogger().info("[WebPanel] IP eliminada de blacklist: " + ip + " (" + ok + ")");
            }
            case "restore-backup" -> {
                Vault v = plugin.getModuleManager().getModule("vault", Vault.class);
                String file = p.get("file");
                if (v != null && v.getBackupScheduler() != null) {
                    plugin.getThreadPoolManager().submit("VaultRestore", () -> {
                        var r = v.getBackupScheduler().restoreBackup(file);
                        plugin.getLogger().info("[WebPanel] Restore " + file + ": " + r.summary());
                        plugin.getAlertSystem().info("WebPanel", "Backup", "Restore " + file + ": " + r.summary());
                    });
                }
                plugin.logAction("WebPanel", "restore:" + file, file, "ok");
            }
            case "freeze" -> playerAction(p.get("uuid"), p.get("name"),
                    pl -> { pl.setWalkSpeed(0f); pl.setFlySpeed(0f); frozenPlayers.add(pl.getUniqueId()); }, "freeze", p);
            case "unfreeze" -> playerAction(p.get("uuid"), p.get("name"),
                    pl -> { pl.setWalkSpeed(0.2f); pl.setFlySpeed(0.1f); frozenPlayers.remove(pl.getUniqueId()); }, "unfreeze", p);
            case "mute" -> playerAction(p.get("uuid"), p.get("name"),
                    pl -> mutedPlayers.add(pl.getUniqueId()), "mute", p);
            case "unmute" -> playerAction(p.get("uuid"), p.get("name"),
                    pl -> mutedPlayers.remove(pl.getUniqueId()), "unmute", p);
            case "change-password" -> {
                String cur = p.getOrDefault("current", "");
                String neu = p.getOrDefault("new", "");
                String uname = sessions.get(token);
                UserInfo u = uname != null ? users.get(uname.toLowerCase()) : null;
                if (u == null || !hash(cur).equals(u.hash()) || neu.isEmpty()) {
                    sendRedirect(ex, "/settings?e=1");
                } else {
                    if (multiUser) plugin.getConfig().set("web-panel.users." + uname + ".password", neu);
                    else plugin.getConfig().set("web-panel.password", neu);
                    plugin.saveConfig();
                    users.put(uname.toLowerCase(), new UserInfo(u.name(), hash(neu), u.role()));
                    if (token != null && "noauth".equals(token)) { /* n/a */ }
                    sendRedirect(ex, "/settings?ok=1");
                }
            }
            case "run-command" -> {
                String cmd = p.getOrDefault("command", "").trim();
                String actor = sessions.getOrDefault(token, "admin");
                if (!cmd.isEmpty()) {
                    Bukkit.getScheduler().runTask(plugin, () -> Bukkit.dispatchCommand(Bukkit.getConsoleSender(), cmd));
                    plugin.getAlertSystem().info("web-panel", actor, "Comando ejecutado desde el panel: " + cmd);
                }
                sendRedirect(ex, "/console?ok=1");
            }
            case "save-config" -> {
                String yaml = p.getOrDefault("yaml", "");
                String actor = sessions.getOrDefault(token, "admin");
                try {
                    java.io.File cfgFile = new java.io.File(plugin.getDataFolder(), "config.yml");
                    try (java.io.FileWriter w = new java.io.FileWriter(cfgFile)) { w.write(yaml); }
                    plugin.reloadConfig();
                    loadConfig();
                    plugin.getAlertSystem().info("web-panel", actor, "Configuración guardada desde el panel");
                    sendRedirect(ex, "/config?ok=1");
                } catch (Exception ex2) {
                    sendHtml(ex, page("Error", nav(token) + "<div class='banner'>No se pudo escribir: "
                            + escapeHtml(ex2.getMessage()) + "</div>", token), "text/html");
                }
            }
            default -> { /* ignore */ }
        }
        sendRedirect(ex, refererOrDashboard(ex));
    }

    private void toggleEmergency(boolean on) {
        Autopilot ap = plugin.getModuleManager().getModule("autopilot", Autopilot.class);
        if (ap == null || ap.getEmergencyMode() == null) return;
        EmergencyMode em = ap.getEmergencyMode();
        if (on && !em.isActive()) { Bukkit.getScheduler().runTask(plugin, em::activate); }
        else if (!on && em.isActive()) { Bukkit.getScheduler().runTask(plugin, em::deactivate); }
    }

    private void playerAction(String uuidStr, String name, java.util.function.Consumer<Player> action, String label, Map<String, String> ctx) {
        try {
            UUID uuid = UUID.fromString(uuidStr);
            Bukkit.getScheduler().runTask(plugin, () -> {
                Player pl = Bukkit.getPlayer(uuid);
                if (pl != null) action.accept(pl);
            });
            plugin.logAction("WebPanel", label, name, "ok");
        } catch (Exception e) {
            plugin.getLogger().warning("[WebPanel] Acción " + label + " falló: " + e.getMessage());
        }
    }

    private String refererOrDashboard(HttpExchange ex) {
        String r = ex.getRequestHeaders().getFirst("Referer");
        if (r != null && r.contains("/")) return r;
        return "/dashboard";
    }

    // ============================================================
    // JSON builders
    // ============================================================

    private JsonObject buildStatusJson() {
        var pm = plugin.getPerformanceMonitor();
        var mm = plugin.getModuleManager();
        JsonObject o = new JsonObject();
        o.addProperty("tps", pm.getCurrentTps());
        o.addProperty("cpu", pm.getCpuUsagePercent());
        o.addProperty("ramUsed", pm.getUsedRamMb());
        o.addProperty("ramTotal", pm.getTotalRamMb());
        o.addProperty("online", collectOnlinePlayers().size());
        o.addProperty("modulesActive", mm.getActiveModuleCount());
        o.addProperty("modulesTotal", mm.getTotalModuleCount());
        o.addProperty("subscription", plugin.getSubscriptionManager().isSubscriptionActive());
        JsonArray tpsH = new JsonArray(); pm.getTpsHistory().forEach(tpsH::add);
        JsonArray ramH = new JsonArray(); pm.getRamHistory().forEach(ramH::add);
        o.add("tpsHistory", tpsH);
        o.add("ramHistory", ramH);
        JsonArray mods = new JsonArray();
        for (SecurityModule m : mm.getAllModules().values()) {
            JsonObject mo = new JsonObject();
            mo.addProperty("name", m.getName());
            mo.addProperty("active", mm.isModuleActive(normalize(m.getName())));
            mods.add(mo);
        }
        o.add("modules", mods);
        Map<String, Object> ss = collectServerStats();
        JsonObject srv = new JsonObject();
        srv.addProperty("uptime", toLong(ss.get("uptime")));
        srv.addProperty("javaVersion", String.valueOf(ss.get("javaVersion")));
        srv.addProperty("os", String.valueOf(ss.get("os")));
        srv.addProperty("cores", toInt(ss.get("cores")));
        srv.addProperty("worlds", toInt(ss.get("worlds")));
        srv.addProperty("entities", toInt(ss.get("entities")));
        srv.addProperty("chunks", toInt(ss.get("chunks")));
        srv.addProperty("diskTotal", toLong(ss.get("diskTotal")));
        srv.addProperty("diskUsed", toLong(ss.get("diskUsed")));
        srv.addProperty("health", toInt(ss.get("health")));
        o.add("server", srv);
        return o;
    }

    private String buildMetricsText() {
        var pm = plugin.getPerformanceMonitor();
        var mm = plugin.getModuleManager();
        Map<String, Object> ss = collectServerStats();
        StringBuilder m = new StringBuilder();
        m.append("# HELP nexussecurity_tps Ticks per second (20 = perfecto).\n").append("# TYPE nexussecurity_tps gauge\n")
                .append("nexussecurity_tps ").append(pm.getCurrentTps()).append("\n");
        m.append("# HELP nexussecurity_cpu_percent Uso de CPU del proceso (0-100).\n").append("# TYPE nexussecurity_cpu_percent gauge\n")
                .append("nexussecurity_cpu_percent ").append(pm.getCpuUsagePercent()).append("\n");
        m.append("# HELP nexussecurity_ram_used_mb RAM usada por la JVM.\n").append("# TYPE nexussecurity_ram_used_mb gauge\n")
                .append("nexussecurity_ram_used_mb ").append(pm.getUsedRamMb()).append("\n");
        m.append("# HELP nexussecurity_ram_total_mb RAM total de la JVM.\n").append("# TYPE nexussecurity_ram_total_mb gauge\n")
                .append("nexussecurity_ram_total_mb ").append(pm.getTotalRamMb()).append("\n");
        m.append("# HELP nexussecurity_players_online Jugadores conectados.\n").append("# TYPE nexussecurity_players_online gauge\n")
                .append("nexussecurity_players_online ").append(collectOnlinePlayers().size()).append("\n");
        m.append("# HELP nexussecurity_modules_active Módulos activos.\n").append("# TYPE nexussecurity_modules_active gauge\n")
                .append("nexussecurity_modules_active ").append(mm.getActiveModuleCount()).append("\n");
        m.append("# HELP nexussecurity_modules_total Módulos totales.\n").append("# TYPE nexussecurity_modules_total gauge\n")
                .append("nexussecurity_modules_total ").append(mm.getTotalModuleCount()).append("\n");
        m.append("# HELP nexussecurity_disk_used_bytes Espacio en disco usado.\n").append("# TYPE nexussecurity_disk_used_bytes gauge\n")
                .append("nexussecurity_disk_used_bytes ").append(toLong(ss.get("diskUsed"))).append("\n");
        m.append("# HELP nexussecurity_disk_total_bytes Espacio en disco total.\n").append("# TYPE nexussecurity_disk_total_bytes gauge\n")
                .append("nexussecurity_disk_total_bytes ").append(toLong(ss.get("diskTotal"))).append("\n");
        m.append("# HELP nexussecurity_entities Entidades cargadas.\n").append("# TYPE nexussecurity_entities gauge\n")
                .append("nexussecurity_entities ").append(toInt(ss.get("entities"))).append("\n");
        m.append("# HELP nexussecurity_chunks Chunks cargados.\n").append("# TYPE nexussecurity_chunks gauge\n")
                .append("nexussecurity_chunks ").append(toInt(ss.get("chunks"))).append("\n");
        m.append("# HELP nexussecurity_worlds Mundos cargados.\n").append("# TYPE nexussecurity_worlds gauge\n")
                .append("nexussecurity_worlds ").append(toInt(ss.get("worlds"))).append("\n");
        m.append("# HELP nexussecurity_health Índice de salud (0-100).\n").append("# TYPE nexussecurity_health gauge\n")
                .append("nexussecurity_health ").append(toInt(ss.get("health"))).append("\n");
        m.append("# HELP nexussecurity_uptime_seconds Tiempo activo.\n").append("# TYPE nexussecurity_uptime_seconds counter\n")
                .append("nexussecurity_uptime_seconds ").append(toLong(ss.get("uptime"))).append("\n");
        long gcCount = 0, gcTime = 0;
        for (java.lang.management.GarbageCollectorMXBean gc : java.lang.management.ManagementFactory.getGarbageCollectorMXBeans()) {
            gcCount += gc.getCollectionCount();
            gcTime += gc.getCollectionTime();
        }
        m.append("# HELP nexussecurity_jvm_gc_collections Total de colecciones GC.\n").append("# TYPE nexussecurity_jvm_gc_collections counter\n")
                .append("nexussecurity_jvm_gc_collections ").append(gcCount).append("\n");
        m.append("# HELP nexussecurity_jvm_gc_time_ms Tiempo total en GC (ms).\n").append("# TYPE nexussecurity_jvm_gc_time_ms counter\n")
                .append("nexussecurity_jvm_gc_time_ms ").append(gcTime).append("\n");
        m.append("# HELP nexussecurity_jvm_threads Hilos activos de la JVM.\n").append("# TYPE nexussecurity_jvm_threads gauge\n")
                .append("nexussecurity_jvm_threads ").append(java.lang.management.ManagementFactory.getThreadMXBean().getThreadCount()).append("\n");
        return m.toString();
    }

    private JsonObject buildPlayersJson() {
        JsonObject o = new JsonObject();
        JsonArray arr = new JsonArray();
        for (Player p : collectOnlinePlayers()) {
            JsonObject pl = new JsonObject();
            pl.addProperty("name", p.getName());
            pl.addProperty("uuid", p.getUniqueId().toString());
            pl.addProperty("ip", p.getAddress() != null ? p.getAddress().getAddress().getHostAddress() : "?");
            pl.addProperty("ping", p.getPing());
            pl.addProperty("op", p.isOp());
            arr.add(pl);
        }
        o.add("players", arr);
        return o;
    }

    // ============================================================
    // CSV
    // ============================================================

    private String eventsCsv() {
        StringBuilder sb = new StringBuilder("timestamp,severity,module,message,ip\n");
        for (AlertSystem.AlertEntry e : plugin.getAlertSystem().getRecentEvents()) {
            sb.append(csv(fmtTime(e.timestamp()))).append(',').append(csv(e.severity())).append(',').append(csv(e.module()))
                    .append(',').append(csv(e.description())).append(',').append(csv(e.source() != null ? e.source() : ""))
                    .append('\n');
        }
        return sb.toString();
    }

    private String auditCsv(Map<String, String> q) {
        String actor = q != null ? q.getOrDefault("actor", "") : "";
        String action = q != null ? q.getOrDefault("action", "") : "";
        String search = q != null ? q.getOrDefault("q", "") : "";
        StringBuilder sb = new StringBuilder("timestamp,actor,action,target,result,ip\n");
        java.text.SimpleDateFormat fmt = new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        for (Map<String, Object> row : plugin.getDatabaseManager().queryAuditLog(actor, action, search, -1, -1, 1000, 0)) {
            long ts = toLong(row.get("timestamp"));
            sb.append(csv(ts > 0 ? fmt.format(new java.util.Date(ts)) : "")).append(',')
                    .append(csv(String.valueOf(row.get("actor")))).append(',')
                    .append(csv(String.valueOf(row.get("action")))).append(',')
                    .append(csv(String.valueOf(row.get("target")))).append(',')
                    .append(csv(String.valueOf(row.get("result")))).append(',')
                    .append(csv(String.valueOf(row.get("ip_address")))).append('\n');
        }
        return sb.toString();
    }

    private String csv(String s) {
        if (s == null) return "";
        String t = s.replace("\"", "\"\"");
        return t.contains(",") || t.contains("\"") || t.contains("\n") ? "\"" + t + "\"" : t;
    }

    // ============================================================
    // Player data (main thread)
    // ============================================================

    private List<Player> collectOnlinePlayers() {
        try {
            return Bukkit.getScheduler().callSyncMethod(plugin, (java.util.concurrent.Callable<List<Player>>)
                    () -> new ArrayList<>(Bukkit.getOnlinePlayers())).get(5, java.util.concurrent.TimeUnit.SECONDS);
        } catch (Exception e) {
            return List.of();
        }
    }

    private PlayerDetail getPlayerDetail(UUID uuid) {
        try {
            return Bukkit.getScheduler().callSyncMethod(plugin, (java.util.concurrent.Callable<PlayerDetail>)
                    () -> computePlayerDetail(uuid)).get(5, java.util.concurrent.TimeUnit.SECONDS);
        } catch (Exception e) {
            return null;
        }
    }

    private PlayerDetail computePlayerDetail(UUID uuid) {
        Player p = Bukkit.getPlayer(uuid);
        if (p == null) return null;
        String ip = p.getAddress() != null ? p.getAddress().getAddress().getHostAddress() : "?";
        Shield shield = plugin.getModuleManager().getModule("shield", Shield.class);
        RateLimiter rl = shield != null ? shield.getRateLimiter() : null;
        HackDetector hd = plugin.getModuleManager().getModule("hackdetector", HackDetector.class);
        List<String> effects = new ArrayList<>();
        p.getActivePotionEffects().forEach(e -> effects.add(e.getType().getName() + " x" + (e.getAmplifier() + 1)));
        return new PlayerDetail(
                p.getName(),
                ip,
                p.getPing(),
                p.getGameMode().name(),
                p.getWorld() != null ? p.getWorld().getName() : "?",
                p.getLocation().getBlockX() + "," + p.getLocation().getBlockY() + "," + p.getLocation().getBlockZ(),
                p.getHealth(),
                p.getFoodLevel(),
                p.getLevel(),
                p.isOp(),
                p.hasPermission("nexussecurity.bypass"),
                p.isFlying(),
                p.isBanned(),
                rl != null && rl.isBanned(ip),
                hd != null ? hd.getViolationCount(uuid) : 0,
                effects
        );
    }

    private record PlayerDetail(String name, String ip, int ping, String gamemode, String world, String coords,
                                double health, int food, int level, boolean op, boolean bypass, boolean flying,
                                boolean banned, boolean ipBanned, int violations, List<String> effects) {}

    // ============================================================
    // HTML helpers
    // ============================================================

    private String statCard(String label, String value, String cls, String extra) {
        return "<div class='card stat " + cls + "'><div class='label'>" + escapeHtml(label) + "</div>" +
                "<div class='value'>" + value + "</div>" + (extra != null ? extra : "") + "</div>";
    }

    private String actionForm(String action, String label, String cls, Map<String, String> hiddenFields) {
        StringBuilder b = new StringBuilder("<form method='post' action='/action'>");
        b.append(hidden("action", action));
        for (Map.Entry<String, String> e : hiddenFields.entrySet()) b.append(hidden(e.getKey(), e.getValue()));
        b.append("<button class='").append(cls).append("'>").append(escapeHtml(label)).append("</button></form>");
        return b.toString();
    }

    private String hidden(String name, String value) {
        return "<input type='hidden' name='" + escapeHtml(name) + "' value='" + escapeHtml(value) + "'>";
    }

    private String severityBadge(String sev) {
        String cls = switch (sev == null ? "" : sev.toLowerCase()) {
            case "critical", "error" -> "bad";
            case "warning" -> "warn";
            default -> "ok";
        };
        return "<span class='dot " + cls + "'></span>" + escapeHtml(sev == null ? "?" : sev);
    }

    private String sparkline(List<? extends Number> vals, String color, double min, double max) {
        if (vals.isEmpty()) return "<span class='muted small'>sin datos</span>";
        int w = 240, h = 44;
        if (max <= min) max = min + 1;
        int n = vals.size();
        StringBuilder pts = new StringBuilder();
        for (int i = 0; i < n; i++) {
            double v = vals.get(i).doubleValue();
            double x = (double) i / (n - 1) * w;
            double y = h - ((v - min) / (max - min)) * h;
            pts.append(String.format(Locale.US, "%.1f,%.1f", x, Math.max(0, Math.min(h, y))));
            if (i < n - 1) pts.append(" ");
        }
        return "<svg class='spark' width='" + w + "' height='" + h + "' viewBox='0 0 " + w + " " + h + "'>" +
                "<polyline fill='none' stroke='" + color + "' stroke-width='2' points='" + pts + "'/></svg>";
    }

    private List<Double> toDouble(List<Long> l) {
        List<Double> out = new ArrayList<>(l.size());
        for (Long v : l) out.add(v.doubleValue());
        return out;
    }

    private String liveScript(String frag) {
        return "<script>function nx_refresh(){fetch('/frag/" + frag + "').then(r=>r.text()).then(h=>{" +
                "var el=document.getElementById('live'); if(el){el.innerHTML=h; var ts=document.getElementById('ts'); " +
                "if(ts) ts.textContent=new Date().toLocaleTimeString();}}).catch(()=>{});}" +
                "setInterval(nx_refresh, 4000);</script>";
    }

    private List<String> moduleNames() {
        List<String> out = new ArrayList<>();
        for (SecurityModule m : plugin.getModuleManager().getAllModules().values()) out.add(m.getName());
        return out;
    }

    private String normalize(String name) { return name.toLowerCase().replace("-", "").replace(" ", ""); }

    private int parseIntSafe(String s, int def) {
        try { return Integer.parseInt(s); } catch (Exception e) { return def; }
    }

    private long toLong(Object o) {
        if (o instanceof Number n) return n.longValue();
        try { return Long.parseLong(String.valueOf(o)); } catch (Exception e) { return 0; }
    }

    private int toInt(Object o) {
        if (o instanceof Number n) return n.intValue();
        try { return Integer.parseInt(String.valueOf(o)); } catch (Exception e) { return 0; }
    }

    private JsonObject tree(String k, String v) { JsonObject o = new JsonObject(); o.addProperty(k, v); return o; }

    // ============================================================
    // IO
    // ============================================================

    private void sendHtml(HttpExchange ex, String html, String type) throws IOException {
        byte[] b = html.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", type + "; charset=utf-8");
        ex.sendResponseHeaders(200, b.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(b); }
    }

    private void sendJson(HttpExchange ex, String json) throws IOException {
        byte[] b = json.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", "application/json; charset=utf-8");
        ex.sendResponseHeaders(200, b.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(b); }
    }

    private void sendCsv(HttpExchange ex, String csv) throws IOException {
        byte[] b = csv.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", "text/csv; charset=utf-8");
        ex.getResponseHeaders().add("Content-Disposition", "attachment; filename=\"nexussecurity_export.csv\"");
        ex.sendResponseHeaders(200, b.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(b); }
    }

    private void sendRedirect(HttpExchange ex, String to) throws IOException {
        ex.getResponseHeaders().add("Location", to);
        ex.sendResponseHeaders(302, -1);
        ex.close();
    }

    private String escapeHtml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#39;");
    }

    private String fmtUptime(long ms) {
        long s = ms / 1000;
        long d = s / 86400; s %= 86400;
        long h = s / 3600; s %= 3600;
        long m = s / 60;
        return (d > 0 ? d + "d " : "") + h + "h " + m + "m";
    }

    private String fmtMB(long bytes) {
        if (bytes <= 0) return "0 MB";
        return String.format("%.1f GB", bytes / (1024.0 * 1024.0 * 1024.0));
    }

    private String kv(String label, String value) {
        return "<div class='kvrow'><span>" + escapeHtml(label) + "</span><b>" + escapeHtml(value) + "</b></div>";
    }

    private Map<String, Object> collectServerStats() {
        Map<String, Object> m = new HashMap<>();
        try {
            long uptime = ManagementFactory.getRuntimeMXBean().getUptime();
            m.put("uptime", uptime);
            m.put("javaVersion", System.getProperty("java.version"));
            m.put("os", System.getProperty("os.name") + " " + System.getProperty("os.arch"));
            m.put("cores", Runtime.getRuntime().availableProcessors());
        } catch (Exception ignored) {}
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> inner = (Map<String, Object>) Bukkit.getScheduler()
                    .callSyncMethod(plugin, (java.util.concurrent.Callable<Object>) () -> {
                        Map<String, Object> r = new HashMap<>();
                        int worlds = Bukkit.getWorlds().size();
                        int entities = 0, chunks = 0;
                        for (var w : Bukkit.getWorlds()) { entities += w.getEntities().size(); chunks += w.getLoadedChunks().length; }
                        r.put("worlds", worlds);
                        r.put("entities", entities);
                        r.put("chunks", chunks);
                        r.put("players", Bukkit.getOnlinePlayers().size());
                        return r;
                    }).get(5, TimeUnit.SECONDS);
            if (inner != null) m.putAll(inner);
        } catch (Exception ignored) {}
        try {
            Path root = Paths.get(".").toAbsolutePath();
            FileStore store = Files.getFileStore(root);
            long total = store.getTotalSpace();
            long usable = store.getUsableSpace();
            m.put("diskTotal", total);
            m.put("diskUsed", total - usable);
        } catch (Exception ignored) {}
        PerformanceMonitor pm = plugin.getPerformanceMonitor();
        double tps = pm != null ? pm.getCurrentTps() : 20.0;
        double cpu = pm != null ? pm.getCpuUsagePercent() : 0.0;
        long ramMax = Runtime.getRuntime().maxMemory();
        long ramUsed = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
        m.put("tps", tps);
        m.put("cpu", cpu);
        m.put("ramUsed", ramUsed);
        m.put("ramMax", ramMax);
        double tpsScore = Math.min(1.0, Math.max(0, tps / 20.0));
        double ramScore = ramMax > 0 ? 1.0 - Math.min(1.0, (double) ramUsed / ramMax) : 1.0;
        double cpuScore = 1.0 - Math.min(1.0, cpu / 100.0);
        int health = (int) (100 * (tpsScore * 0.4 + ramScore * 0.4 + cpuScore * 0.2));
        m.put("health", health);
        return m;
    }

    private String fmtTime(long epochMillis) {
        if (epochMillis <= 0) return "—";
        return java.time.Instant.ofEpochMilli(epochMillis)
                .atZone(java.time.ZoneId.systemDefault())
                .format(java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
    }

    // ============================================================
    // Hashing + TOTP (2FA) — no external dependencies
    // ============================================================

    private String hash(String s) {
        return nx.zsanchez.nexussecurity.util.CryptoUtil.hash(s);
    }

    private String generateBase32Secret(int bytes) {
        return nx.zsanchez.nexussecurity.util.CryptoUtil.randomBase32Secret(bytes);
    }

    private boolean verifyTotp(String code) {
        return nx.zsanchez.nexussecurity.util.CryptoUtil.verifyTotp(totpSecret, code);
    }

    private String style() {
        return "<style>" +
                "*,body{margin:0;font-family:system-ui,Segoe UI,Roboto,sans-serif;background:#0f1117;color:#e6e6e6}" +
                "nav{display:flex;gap:6px;padding:10px 16px;background:#171a22;border-bottom:1px solid #232733;flex-wrap:wrap}" +
                "nav a{color:#9fb3c8;text-decoration:none;padding:6px 10px;border-radius:6px;font-size:14px}" +
                "nav a:hover{background:#222838;color:#fff}nav a.right{margin-left:auto;color:#f87171}" +
                ".wrap{max-width:1100px;margin:0 auto;padding:18px}" +
                ".page{display:flex;align-items:center;gap:12px;margin-bottom:12px}" +
                ".page h1{font-size:22px;margin:0}.ts{margin-left:auto;color:#7c8aa0;font-size:13px}" +
                ".cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:12px;margin-bottom:14px}" +
                ".card{background:#171a22;border:1px solid #232733;border-radius:10px;padding:14px;margin-bottom:14px}" +
                ".card.stat .label{font-size:12px;color:#7c8aa0}.card.stat .value{font-size:20px;font-weight:600;margin-top:4px}" +
                ".card h3{margin:0 0 10px;font-size:15px;color:#cbd5e1}" +
                "table.grid{width:100%;border-collapse:collapse;font-size:13px}" +
                "table.grid th{text-align:left;color:#7c8aa0;font-weight:600;padding:6px 8px;border-bottom:1px solid #232733}" +
                "table.grid td{padding:6px 8px;border-bottom:1px solid #1c2029}" +
                ".dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px}" +
                ".dot.ok{background:#4ade80}.dot.bad{background:#f87171}.dot.warn{background:#fbbf24}.dot.muted{background:#475569}" +
                ".btn{background:#2563eb;color:#fff;border:0;padding:8px 12px;border-radius:7px;cursor:pointer;font-size:13px;text-decoration:none;display:inline-block}" +
                ".btn:hover{background:#1d4ed8}.btn.ok{background:#16a34a}.btn.danger{background:#dc2626}.btn.warn{background:#d97706}" +
                ".btn.small{padding:5px 9px;font-size:12px}.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:8px}" +
                "input,select{background:#0f1117;color:#e6e6e6;border:1px solid #2b3344;border-radius:6px;padding:7px 9px;font-size:13px}" +
                ".banner{background:#3b1d1d;border:1px solid #7f1d1d;color:#fca5a5;padding:10px 12px;border-radius:8px;margin-bottom:12px}" +
                ".upsell{background:linear-gradient(90deg,#1e293b,#312e81);border:1px solid #4f46e5;color:#e0e7ff;padding:12px 14px;border-radius:10px;margin-bottom:14px;line-height:1.5}" +
                ".premiumok{background:#052e16;border:1px solid #16a34a;color:#bbf7d0;padding:10px 12px;border-radius:10px;margin-bottom:14px}" +
                ".plan{font-size:12px;font-weight:700;padding:4px 9px;border-radius:20px;align-self:center}" +
                ".plan.premium{background:#16a34a;color:#062b13}.plan.free{background:#3f3f46;color:#e4e4e7}" +
                "nav a.right{margin-left:8px;color:#9fb3c8}" +
                ".msg{padding:8px 10px;border-radius:7px;margin:8px 0;font-size:13px}.msg.err{background:#3b1d1d;color:#fca5a5}.msg.warn{background:#3b2f10;color:#fde68a}" +
                ".muted{color:#7c8aa0}.small{font-size:12px}.mono{font-family:ui-monospace,Menlo,monospace}" +
                ".avatar{width:24px;height:24px;border-radius:4px;vertical-align:middle}.login{max-width:340px;margin:8vh auto;background:#171a22;border:1px solid #232733;border-radius:12px;padding:24px;text-align:center}" +
                ".brand{font-size:20px;font-weight:700;margin-bottom:6px}.login input{width:100%;margin:8px 0}.login button{width:100%}" +
                "footer{text-align:center;padding:14px;color:#5b6675;font-size:12px}.spark{display:block;margin-top:4px}" +
                ".bar{height:8px;border-radius:4px;background:#4ade80;min-width:2px;max-width:100%}" +
                ".kv{display:grid;grid-template-columns:1fr 1fr;gap:2px 18px}.kvrow{display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid #1c2029;font-size:13px}.kvrow span{color:#7c8aa0}.health{margin-top:10px;font-size:13px}.health .bar{margin-top:5px;height:10px}" +
                ".row{display:flex;flex-wrap:wrap;gap:8px;align-items:center}.col{display:flex;flex-direction:column;gap:8px;max-width:320px}" +
                "input,select,textarea{background:#0f1117;color:#e6edf6;border:1px solid #232733;border-radius:7px;padding:8px 10px;font-size:13px}" +
                "pre.console{background:#000;color:#b7f7c8;max-height:60vh;overflow:auto;padding:10px;border-radius:8px;font-size:12px;white-space:pre-wrap;word-break:break-word}" +
                ".toast{position:fixed;right:16px;bottom:16px;background:#7f1d1d;color:#fff;padding:10px 14px;border-radius:8px;font-size:13px;box-shadow:0 6px 20px rgba(0,0,0,.4);z-index:99;animation:nxpop .2s ease}" +
                "@keyframes nxpop{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}" +
                "body.light{background:#eef1f6;color:#111827}body.light .card,body.light nav,body.light .login,body.light .wrap{background:#fff;color:#111827;border-color:#d7dde6}" +
                "body.light nav a,body.light .plan{color:#334155}body.light pre.console{background:#0b0f0a;color:#b7f7c8}" +
                "body.light input,body.light select,body.light textarea{background:#f8fafc;color:#111827;border-color:#cbd5e1}" +
                "@media (max-width:720px){.kv{grid-template-columns:1fr}nav{flex-wrap:wrap}.cards{grid-template-columns:1fr 1fr}.container{width:100%}}" +
                "@media (max-width:480px){.cards{grid-template-columns:1fr}nav a{padding:6px 8px}}" +
                "</style>";
    }
}
