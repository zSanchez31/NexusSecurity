package nx.zsanchez.nexussecurity.util;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;
import java.util.logging.Logger;

/**
 * Utility class for cryptographic operations used across NexusSecurity modules.
 * Provides SHA-256 hashing, HMAC validation and secure random generation.
 * All methods are thread-safe and use JDK built-in cryptography.
 */
public final class HashUtil {

    private static final Logger LOGGER = Logger.getLogger(HashUtil.class.getName());
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private HashUtil() {}

    /**
     * Computes the SHA-256 hash of a byte array.
     *
     * @param data The input bytes
     * @return Lowercase hex-encoded SHA-256 hash, or empty string on error
     */
    public static String sha256(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data);
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            LOGGER.severe("SHA-256 algorithm not available: " + e.getMessage());
            return "";
        }
    }

    /**
     * Computes the SHA-256 hash of a string (UTF-8 encoded).
     *
     * @param text The input string
     * @return Lowercase hex-encoded SHA-256 hash
     */
    public static String sha256(String text) {
        if (text == null) return "";
        return sha256(text.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Computes the SHA-256 hash of a file.
     * This operation reads the entire file and should be called from an async thread.
     *
     * @param filePath Path to the file
     * @return Lowercase hex-encoded SHA-256 hash, or empty string if file not readable
     */
    public static String sha256File(Path filePath) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] fileBytes = Files.readAllBytes(filePath);
            byte[] hash = digest.digest(fileBytes);
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            LOGGER.severe("SHA-256 algorithm not available: " + e.getMessage());
            return "";
        } catch (Exception e) {
            LOGGER.warning("Cannot hash file " + filePath + ": " + e.getMessage());
            return "";
        }
    }

    /**
     * Computes the MD5 hash of a string. Used only for non-security purposes (e.g., cache keys).
     *
     * @param text The input string
     * @return Lowercase hex-encoded MD5 hash
     */
    public static String md5(String text) {
        try {
            MessageDigest digest = MessageDigest.getInstance("MD5");
            byte[] hash = digest.digest(text.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            return text; // Fallback to raw text if MD5 unavailable
        }
    }

    /**
     * Anonymizes an IP address by hashing it with SHA-256.
     * Used for anonymous threat sharing without exposing real IPs.
     *
     * @param ipAddress The IP address string
     * @return SHA-256 hash of the IP
     */
    public static String anonymizeIp(String ipAddress) {
        return sha256("nexussecurity:" + ipAddress);
    }

    /**
     * Generates a cryptographically secure random token of the specified byte length,
     * encoded as Base64.
     *
     * @param byteLength The number of random bytes (encoded result will be longer)
     * @return Base64-encoded secure random token
     */
    public static String generateSecureToken(int byteLength) {
        byte[] bytes = new byte[byteLength];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * Constant-time comparison of two strings to prevent timing attacks.
     * Use this when comparing hashes or secrets.
     *
     * @param a First string
     * @param b Second string
     * @return true if both strings are equal
     */
    public static boolean secureEquals(String a, String b) {
        if (a == null || b == null) return a == b;
        byte[] aBytes = a.getBytes(StandardCharsets.UTF_8);
        byte[] bBytes = b.getBytes(StandardCharsets.UTF_8);
        if (aBytes.length != bBytes.length) return false;
        int diff = 0;
        for (int i = 0; i < aBytes.length; i++) {
            diff |= aBytes[i] ^ bBytes[i];
        }
        return diff == 0;
    }
}
