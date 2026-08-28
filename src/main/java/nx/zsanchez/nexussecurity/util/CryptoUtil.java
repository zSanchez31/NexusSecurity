package nx.zsanchez.nexussecurity.util;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Small, dependency-free cryptography helpers used by the web panel (password hashing,
 * TOTP / 2FA). Kept in its own class so it can be unit-tested without a Bukkit server.
 */
public final class CryptoUtil {

    private static final String B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    private CryptoUtil() {}

    /** SHA-256 hex digest of the given string (UTF-8). */
    public static String hash(String s) {
        if (s == null) return "";
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte x : d) sb.append(String.format("%02x", x));
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    /** Generates a random Base32 secret of {@code bytes} raw bytes (for TOTP). */
    public static String randomBase32Secret(int bytes) {
        byte[] r = new byte[bytes];
        new SecureRandom().nextBytes(r);
        return base32Encode(r);
    }

    public static String base32Encode(byte[] data) {
        StringBuilder sb = new StringBuilder();
        int bits = 0, value = 0;
        for (byte b : data) {
            value = (value << 8) | (b & 0xff);
            bits += 8;
            while (bits >= 5) {
                sb.append(B32.charAt((value >>> (bits - 5)) & 0x1f));
                bits -= 5;
            }
        }
        if (bits > 0) sb.append(B32.charAt((value << (5 - bits)) & 0x1f));
        return sb.toString();
    }

    public static byte[] base32Decode(String s) {
        if (s == null) return new byte[0];
        s = s.replace("=", "").toUpperCase();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int bits = 0, value = 0;
        for (int i = 0; i < s.length(); i++) {
            int idx = B32.indexOf(s.charAt(i));
            if (idx < 0) continue;
            value = (value << 5) | idx;
            bits += 5;
            if (bits >= 8) {
                out.write((value >>> (bits - 8)) & 0xff);
                bits -= 8;
            }
        }
        return out.toByteArray();
    }

    /** RFC 6238 TOTP code (6 digits) for the given 30s counter. */
    public static int totp(byte[] key, long counter) throws Exception {
        byte[] msg = new byte[8];
        for (int i = 7; i >= 0; i--) {
            msg[i] = (byte) (counter & 0xff);
            counter >>= 8;
        }
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(new SecretKeySpec(key, "HmacSHA1"));
        byte[] h = mac.doFinal(msg);
        int off = h[h.length - 1] & 0xf;
        int bin = ((h[off] & 0x7f) << 24) | ((h[off + 1] & 0xff) << 16)
                | ((h[off + 2] & 0xff) << 8) | (h[off + 3] & 0xff);
        return bin % 1_000_000;
    }

    /** Validates a 6-digit TOTP code, allowing +/-1 step of clock drift. */
    public static boolean verifyTotp(String base32Secret, String code) {
        if (base32Secret == null || base32Secret.isEmpty() || code == null || code.isEmpty()) return false;
        try {
            byte[] key = base32Decode(base32Secret);
            long counter = System.currentTimeMillis() / 30_000L;
            String cur = String.format("%06d", totp(key, counter));
            String prev = String.format("%06d", totp(key, counter - 1));
            String next = String.format("%06d", totp(key, counter + 1));
            return Arrays.equals(code.getBytes(), cur.getBytes())
                    || Arrays.equals(code.getBytes(), prev.getBytes())
                    || Arrays.equals(code.getBytes(), next.getBytes());
        } catch (Exception e) {
            return false;
        }
    }
}
