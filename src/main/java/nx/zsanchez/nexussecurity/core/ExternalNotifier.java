package nx.zsanchez.nexussecurity.core;

import nx.zsanchez.nexussecurity.NexusSecurity;

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
        try {
            minSeverity = AlertSystem.Severity.valueOf(
                    cfg.getString("notifications.external.min-level", "CRITICAL").toUpperCase());
        } catch (IllegalArgumentException e) {
            minSeverity = AlertSystem.Severity.CRITICAL;
        }
        if (enabled && discordWebhook.isEmpty() && (telegramToken.isEmpty() || telegramChatId.isEmpty())) {
            enabled = false;
            plugin.getLogger().warning("[ExternalNotifier] Deshabilitado: falta webhook de Discord o token/chat-id de Telegram.");
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

        String text = "🛡 **NexusSecurity** [" + entry.severity() + "] " + entry.module() +
                "\n📍 " + entry.source() + "\n📝 " + entry.description();

        if (!discordWebhook.isEmpty()) {
            final String discordPayload = jsonEscape(text);
            plugin.getThreadPoolManager().submit("external-notifier-discord", () -> sendDiscord(discordPayload));
        }
        if (!telegramToken.isEmpty() && !telegramChatId.isEmpty()) {
            plugin.getThreadPoolManager().submit("external-notifier-telegram", () -> sendTelegram(text));
        }
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
