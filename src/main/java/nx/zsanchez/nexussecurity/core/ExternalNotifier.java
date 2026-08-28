package nx.zsanchez.nexussecurity.core;

import nx.zsanchez.nexussecurity.NexusSecurity;

import java.io.IOException;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.function.Consumer;

/**
 * Sends critical alerts to external services (Discord webhook / Telegram bot).
 * Subscribes to {@link AlertSystem} and POSTs matching alerts off the main thread.
 */
public class ExternalNotifier {

    private final NexusSecurity plugin;
    private final AlertSystem alertSystem;
    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    private boolean enabled = false;
    private String discordWebhook = "";
    private String telegramToken = "";
    private String telegramChatId = "";
    private String slackWebhook = "";
    private String genericWebhook = "";
    private String pushoverToken = "";
    private String pushoverUser = "";
    private String smtpHost = "";
    private int smtpPort = 25;
    private String smtpUser = "";
    private String smtpPass = "";
    private String smtpFrom = "";
    private String smtpTo = "";
    private boolean slackEnabled = false;
    private boolean genericEnabled = false;
    private boolean pushoverEnabled = false;
    private boolean smtpEnabled = false;
    private AlertSystem.Severity minSeverity = AlertSystem.Severity.CRITICAL;

    private final Consumer<AlertSystem.AlertEntry> consumer = this::onAlert;

    public ExternalNotifier(NexusSecurity plugin, AlertSystem alertSystem) {
        this.plugin = plugin;
        this.alertSystem = alertSystem;
    }

    public void loadConfig() {
        var cfg = plugin.getConfig();
        enabled = cfg.getBoolean("notifications.external.enabled", false);
        discordWebhook = cfg.getString("notifications.discord.webhook-url", "");
        telegramToken = cfg.getString("notifications.telegram.token", "");
        telegramChatId = cfg.getString("notifications.telegram.chat-id", "");
        slackWebhook = cfg.getString("notifications.slack.webhook-url", "");
        genericWebhook = cfg.getString("notifications.webhook.url", "");
        pushoverToken = cfg.getString("notifications.pushover.token", "");
        pushoverUser = cfg.getString("notifications.pushover.user", "");
        smtpHost = cfg.getString("notifications.smtp.host", "");
        smtpPort = cfg.getInt("notifications.smtp.port", 25);
        smtpUser = cfg.getString("notifications.smtp.user", "");
        smtpPass = cfg.getString("notifications.smtp.password", "");
        smtpFrom = cfg.getString("notifications.smtp.from", "");
        smtpTo = cfg.getString("notifications.smtp.to", "");
        slackEnabled = enabled && !slackWebhook.isEmpty();
        genericEnabled = enabled && !genericWebhook.isEmpty();
        pushoverEnabled = enabled && !pushoverToken.isEmpty() && !pushoverUser.isEmpty();
        smtpEnabled = enabled && !smtpHost.isEmpty() && !smtpTo.isEmpty();
        try {
            minSeverity = AlertSystem.Severity.valueOf(
                    cfg.getString("notifications.external.min-level", "CRITICAL").toUpperCase());
        } catch (IllegalArgumentException e) {
            minSeverity = AlertSystem.Severity.CRITICAL;
        }
        if (enabled && discordWebhook.isEmpty() && (telegramToken.isEmpty() || telegramChatId.isEmpty())
                && slackWebhook.isEmpty() && genericWebhook.isEmpty()
                && (pushoverToken.isEmpty() || pushoverUser.isEmpty()) && smtpHost.isEmpty()) {
            enabled = false;
            plugin.getLogger().warning("[ExternalNotifier] Deshabilitado: no hay ningún destino configurado.");
        }
    }

    public void start() {
        if (enabled) alertSystem.subscribe(consumer);
    }

    public void stop() {
        alertSystem.unsubscribe(consumer);
    }

    private void onAlert(AlertSystem.AlertEntry entry) {
        AlertSystem.Severity sev;
        try {
            sev = AlertSystem.Severity.valueOf(entry.severity());
        } catch (IllegalArgumentException e) {
            return;
        }
        if (!sev.isAtLeast(minSeverity)) return;

        String text = "NexusSecurity [" + entry.severity() + "] " + entry.module() +
                "\nOrigen: " + entry.source() + "\nDetalle: " + entry.description();

        if (!discordWebhook.isEmpty()) {
            final String discordPayload = jsonEscape(text);
            plugin.getThreadPoolManager().submit("external-notifier-discord", () -> sendDiscord(discordPayload));
        }
        if (!telegramToken.isEmpty() && !telegramChatId.isEmpty()) {
            plugin.getThreadPoolManager().submit("external-notifier-telegram", () -> sendTelegram(text));
        }
        if (slackEnabled) {
            plugin.getThreadPoolManager().submit("external-notifier-slack", () -> sendSlack(text));
        }
        if (genericEnabled) {
            plugin.getThreadPoolManager().submit("external-notifier-webhook", () -> sendGeneric(entry));
        }
        if (pushoverEnabled) {
            plugin.getThreadPoolManager().submit("external-notifier-pushover", () -> sendPushover(text));
        }
        if (smtpEnabled) {
            plugin.getThreadPoolManager().submit("external-notifier-smtp", () -> sendSmtp(entry));
        }
    }

    private void sendSlack(String text) {
        try {
            String body = "{\"text\":\"" + jsonEscape(text) + "\"}";
            postJson(slackWebhook, body);
        } catch (Exception e) {
            plugin.getLogger().warning("[ExternalNotifier] Error enviando a Slack: " + e.getMessage());
        }
    }

    private void sendGeneric(AlertSystem.AlertEntry entry) {
        try {
            String body = "{\"module\":\"" + jsonEscape(entry.module()) + "\",\"severity\":\"" +
                    jsonEscape(entry.severity()) + "\",\"source\":\"" + jsonEscape(entry.source()) +
                    "\",\"message\":\"" + jsonEscape(entry.description()) + "\"}";
            postJson(genericWebhook, body);
        } catch (Exception e) {
            plugin.getLogger().warning("[ExternalNotifier] Error enviando a webhook: " + e.getMessage());
        }
    }

    private void sendPushover(String text) {
        try {
            String body = "token=" + urlEncode(pushoverToken) + "&user=" + urlEncode(pushoverUser) +
                    "&message=" + urlEncode(text) + "&title=" + urlEncode("NexusSecurity");
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(java.net.URI.create("https://api.pushover.net/1/messages.json"))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();
            http.send(req, HttpResponse.BodyHandlers.discarding());
        } catch (Exception e) {
            plugin.getLogger().warning("[ExternalNotifier] Error enviando a Pushover: " + e.getMessage());
        }
    }

    private void sendSmtp(AlertSystem.AlertEntry entry) {
        try (java.net.Socket socket = new java.net.Socket(smtpHost, smtpPort)) {
            socket.setSoTimeout(15000);
            var in = new java.io.BufferedReader(new java.io.InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
            var out = new java.io.PrintWriter(new java.io.OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8), true);
            expect(in, 220);
            out.print("EHLO nexussecurity\r\n"); out.flush(); readReplies(in);
            out.print("STARTTLS\r\n"); out.flush();
            try { expect(in, 220); } catch (Exception ex) { /* TLS opcional */ }
            javax.net.ssl.SSLSocket s;
            try {
                var ssl = (javax.net.ssl.SSLSocketFactory) javax.net.ssl.SSLSocketFactory.getDefault();
                s = (javax.net.ssl.SSLSocket) ssl.createSocket(socket, smtpHost, smtpPort, true);
            } catch (Exception tlsEx) {
                plugin.getLogger().warning("[ExternalNotifier] SMTP sin STARTTLS: " + tlsEx.getMessage());
                return;
            }
            var sin = new java.io.BufferedReader(new java.io.InputStreamReader(s.getInputStream(), StandardCharsets.UTF_8));
            var sout = new java.io.PrintWriter(new java.io.OutputStreamWriter(s.getOutputStream(), StandardCharsets.UTF_8), true);
            expect(sin, 220);
            sin.readLine(); // saludo post-TLS
            sout.print("EHLO nexussecurity\r\n"); sout.flush(); readReplies(sin);
            if (!smtpUser.isEmpty() && !smtpPass.isEmpty()) {
                sout.print("AUTH LOGIN\r\n"); sout.flush(); expect(sin, 334);
                sout.print(java.util.Base64.getEncoder().encodeToString(smtpUser.getBytes(StandardCharsets.UTF_8)) + "\r\n"); sout.flush(); expect(sin, 334);
                sout.print(java.util.Base64.getEncoder().encodeToString(smtpPass.getBytes(StandardCharsets.UTF_8)) + "\r\n"); sout.flush(); expect(sin, 235);
            }
            sout.print("MAIL FROM:<" + smtpFrom + ">\r\n"); sout.flush(); expect(sin, 250);
            sout.print("RCPT TO:<" + smtpTo + ">\r\n"); sout.flush(); expect(sin, 250);
            sout.print("DATA\r\n"); sout.flush(); expect(sin, 354);
            sout.print("From: NexusSecurity <" + smtpFrom + ">\r\nTo: " + smtpTo + "\r\nSubject: [NexusSecurity] " + entry.severity() + " " + entry.module() + "\r\n\r\n" + entry.description() + "\r\n.\r\n"); sout.flush(); expect(sin, 250);
            sout.print("QUIT\r\n"); sout.flush();
            s.close();
        } catch (Exception e) {
            plugin.getLogger().warning("[ExternalNotifier] Error enviando SMTP: " + e.getMessage());
        }
    }

    private void postJson(String url, String body) throws Exception {
        HttpRequest req = HttpRequest.newBuilder()
                .uri(java.net.URI.create(url))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        http.send(req, HttpResponse.BodyHandlers.discarding());
    }

    private void expect(java.io.BufferedReader in, int code) throws IOException {
        String line = in.readLine();
        if (line == null || !line.startsWith(String.valueOf(code))) {
            throw new IOException("Respuesta SMTP inesperada: " + line);
        }
    }

    private void readReplies(java.io.BufferedReader in) throws IOException {
        String line;
        do {
            line = in.readLine();
        } while (line != null && line.startsWith("250-"));
    }

    private void sendDiscord(String escapedText) {
        try {
            String body = "{\"content\":\"" + escapedText + "\"}";
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(java.net.URI.create(discordWebhook))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();
            http.send(req, HttpResponse.BodyHandlers.discarding());
        } catch (Exception e) {
            plugin.getLogger().warning("[ExternalNotifier] Error enviando a Discord: " + e.getMessage());
        }
    }

    private void sendTelegram(String text) {
        try {
            String body = "chat_id=" + urlEncode(telegramChatId) +
                    "&text=" + urlEncode(text) + "&parse_mode=Markdown";
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(java.net.URI.create("https://api.telegram.org/bot" + telegramToken + "/sendMessage"))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();
            http.send(req, HttpResponse.BodyHandlers.discarding());
        } catch (Exception e) {
            plugin.getLogger().warning("[ExternalNotifier] Error enviando a Telegram: " + e.getMessage());
        }
    }

    private String urlEncode(String s) {
        return URLEncoder.encode(s == null ? "" : s, StandardCharsets.UTF_8);
    }

    private String jsonEscape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }
}
