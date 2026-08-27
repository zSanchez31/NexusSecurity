package nx.zsanchez.nexussecurity.api.model;

/**
 * Represents the response from the NexusSecurity subscription validation API.
 * Parsed from JSON returned by the validation endpoint.
 */
public class SubscriptionResponse {

    /** Whether the API key is currently valid and active. */
    private boolean valid;

    /** Human-readable status message from the server. */
    private String message;

    /** Unix epoch milliseconds when the subscription expires. -1 if unknown. */
    private long expiresAt;

    /** The plan/tier associated with this API key. */
    private String plan;

    /** Server ID assigned by the subscription system. */
    private String serverId;

    /** Whether all premium features are unlocked. */
    private boolean premiumFeaturesEnabled;

    // Default constructor for Gson deserialization
    public SubscriptionResponse() {}

    /**
     * Creates a local "invalid" response used when API is unreachable.
     *
     * @param message Reason for invalidity
     * @return SubscriptionResponse marked as invalid
     */
    public static SubscriptionResponse invalid(String message) {
        SubscriptionResponse r = new SubscriptionResponse();
        r.valid = false;
        r.message = message;
        r.expiresAt = -1;
        r.plan = "NONE";
        r.premiumFeaturesEnabled = false;
        return r;
    }

    public static SubscriptionResponse valid(String plan, long expiresAt, String message) {
        SubscriptionResponse r = new SubscriptionResponse();
        r.valid = true;
        r.message = message;
        r.expiresAt = expiresAt;
        r.plan = plan;
        r.premiumFeaturesEnabled = true;
        return r;
    }

    /**
     * Creates a local "valid" response used during grace period.
     *
     * @param expiresAt Cached expiry timestamp
     * @return SubscriptionResponse marked as valid (grace mode)
     */
    public static SubscriptionResponse gracePeriod(long expiresAt) {
        SubscriptionResponse r = new SubscriptionResponse();
        r.valid = true;
        r.message = "Grace period active — API server unreachable";
        r.expiresAt = expiresAt;
        r.plan = "CACHED";
        r.premiumFeaturesEnabled = true;
        return r;
    }

    // ============================================================
    // GETTERS
    // ============================================================

    /** @return true if the subscription is valid and active */
    public boolean isValid() { return valid; }

    /** @return Status message from the API */
    public String getMessage() { return message != null ? message : ""; }

    /** @return Expiry timestamp in epoch milliseconds, -1 if unknown */
    public long getExpiresAt() { return expiresAt; }

    /** @return Subscription plan name */
    public String getPlan() { return plan != null ? plan : "UNKNOWN"; }

    /** @return Assigned server ID */
    public String getServerId() { return serverId; }

    /** @return Whether all premium features are enabled */
    public boolean isPremiumFeaturesEnabled() { return premiumFeaturesEnabled; }

    @Override
    public String toString() {
        return "SubscriptionResponse{valid=" + valid + ", plan=" + plan +
                ", expiresAt=" + expiresAt + ", message='" + message + "'}";
    }
}
