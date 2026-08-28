package nx.zsanchez.nexussecurity.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class CryptoUtilTest {

    @Test
    void hashIsStableAndDiffers() {
        String a = CryptoUtil.hash("NexusSecurity123");
        assertEquals(a, CryptoUtil.hash("NexusSecurity123"));
        assertNotEquals(a, CryptoUtil.hash("other"));
        assertEquals(64, a.length());
    }

    @Test
    void hashHandlesNullAndEmpty() {
        assertEquals("", CryptoUtil.hash(null));
        assertEquals(CryptoUtil.hash(""), CryptoUtil.hash(""));
    }

    @Test
    void base32RoundTrips() {
        byte[] data = {0, 1, 2, 3, (byte) 255, (byte) 128, 42};
        String enc = CryptoUtil.base32Encode(data);
        assertArrayEquals(data, CryptoUtil.base32Decode(enc));
    }

    @Test
    void base32DecodesLowercaseWithPadding() {
        byte[] data = {9, 9, 9};
        String enc = CryptoUtil.base32Encode(data) + "====";
        assertArrayEquals(data, CryptoUtil.base32Decode(enc));
    }

    @Test
    void totpVerifiesWithinDrift() throws Exception {
        String secret = CryptoUtil.randomBase32Secret(16);
        byte[] key = CryptoUtil.base32Decode(secret);
        long counter = System.currentTimeMillis() / 30_000L;
        String code = String.format("%06d", CryptoUtil.totp(key, counter));
        assertTrue(CryptoUtil.verifyTotp(secret, code));
        assertFalse(CryptoUtil.verifyTotp(secret, "000000"));
    }
}
