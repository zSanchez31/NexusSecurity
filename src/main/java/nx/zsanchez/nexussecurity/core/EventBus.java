package nx.zsanchez.nexussecurity.core;

import nx.zsanchez.nexussecurity.NexusSecurity;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;
import java.util.logging.Logger;

/**
 * Lightweight internal event bus for communication between NexusSecurity modules.
 * Allows modules to publish events and subscribe to events without direct coupling.
 *
 * <p>All listeners are called synchronously on the thread that published the event.
 * If you need async processing, the listener should submit work to {@link ThreadPoolManager}.</p>
 *
 * <p>Standard event types are defined as constants in this class.</p>
 */
public class EventBus {

    // ============================================================
    // STANDARD EVENT TYPE CONSTANTS
    // ============================================================

    /** Published when a suspicious IP attempts to connect. Data: ip (String) */
    public static final String EVENT_SUSPICIOUS_IP     = "suspicious_ip";
    /** Published when a VPN/proxy connection is detected. Data: ip (String) */
    public static final String EVENT_VPN_DETECTED      = "vpn_detected";
    /** Published when a player hack violation is detected. Data: playerName, violationType */
    public static final String EVENT_HACK_DETECTED     = "hack_detected";
    /** Published when a file integrity violation is found. Data: filePath, expected, actual */
    public static final String EVENT_FILE_MODIFIED     = "file_modified";
    /** Published when subscription is validated. Data: expiryDate (long) */
    public static final String EVENT_SUBSCRIPTION_OK   = "subscription_ok";
    /** Published when subscription expires or is invalid. */
    public static final String EVENT_SUBSCRIPTION_FAIL = "subscription_fail";
    /** Published when a threat is detected from intelligence feeds. Data: ip, score */
    public static final String EVENT_THREAT_DETECTED   = "threat_detected";
    /** Published when an anomaly is detected by DefenderAI. Data: type, score */
    public static final String EVENT_ANOMALY_DETECTED  = "anomaly_detected";
    /** Published when emergency mode is activated. */
    public static final String EVENT_EMERGENCY_MODE    = "emergency_mode";
    /** Published on each performance metrics cycle. Data: tps, cpu, ram */
    public static final String EVENT_METRICS_UPDATE    = "metrics_update";
    /** Published when JVM memory crosses a warning/critical threshold. Data: level, usedBytes, maxBytes, percent */
    public static final String EVENT_MEMORY_WARNING    = "memory_warning";

    private final Logger logger;
    /** Map of event type to list of listeners. */
    private final Map<String, List<Consumer<Map<String, Object>>>> listeners = new ConcurrentHashMap<>();

    /**
     * Creates a new EventBus.
     *
     * @param plugin The main plugin instance
     */
    public EventBus(NexusSecurity plugin) {
        this.logger = plugin.getLogger();
    }

    /**
     * Subscribes to an event type.
     *
     * @param eventType The event type to subscribe to (use constants defined in this class)
     * @param listener  The consumer that will handle the event. Receives a data map.
     */
    public void subscribe(String eventType, Consumer<Map<String, Object>> listener) {
        listeners.computeIfAbsent(eventType, k -> new CopyOnWriteArrayList<>()).add(listener);
    }

    /**
     * Publishes an event to all registered listeners.
     *
     * @param eventType The event type (use constants defined in this class)
     * @param data      Key-value pairs of event data. Keys depend on event type.
     */
    public void publish(String eventType, Map<String, Object> data) {
        List<Consumer<Map<String, Object>>> eventListeners = listeners.get(eventType);
        if (eventListeners == null || eventListeners.isEmpty()) return;

        for (Consumer<Map<String, Object>> listener : eventListeners) {
            try {
                listener.accept(data);
            } catch (Exception e) {
                logger.warning("[EventBus] Listener threw exception for event '" + eventType + "': " + e.getMessage());
            }
        }
    }

    /**
     * Convenience method to publish an event with a single key-value pair.
     *
     * @param eventType The event type
     * @param key       Data key
     * @param value     Data value
     */
    public void publish(String eventType, String key, Object value) {
        Map<String, Object> data = new HashMap<>();
        data.put(key, value);
        publish(eventType, data);
    }

    /**
     * Convenience method to publish a parameterless event.
     *
     * @param eventType The event type
     */
    public void publish(String eventType) {
        publish(eventType, Collections.emptyMap());
    }

    /**
     * Removes all listeners for a given event type.
     * Useful when a module is disabled and its listeners should be removed.
     *
     * @param eventType The event type to clear
     */
    public void clearListeners(String eventType) {
        listeners.remove(eventType);
    }

    /**
     * Removes all registered listeners.
     * Called on plugin disable.
     */
    public void clearAll() {
        listeners.clear();
    }

    /**
     * Returns the number of listeners registered for an event type.
     *
     * @param eventType The event type
     * @return Listener count
     */
    public int getListenerCount(String eventType) {
        List<?> list = listeners.get(eventType);
        return list == null ? 0 : list.size();
    }
}
