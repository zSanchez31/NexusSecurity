package nx.zsanchez.nexussecurity.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ApiKeyUtilTest {

    @Test
    void generatedKeysMatchFormat() {
        for (int i = 0; i < 100; i++) {
            String key = ApiKeyUtil.generate();
            assertTrue(ApiKeyUtil.isValidFormat(key), "generated key should be valid: " + key);
            assertTrue(key.startsWith("sk-"));
            assertEquals(27, key.length());
        }
    }

    @Test
    void rejectsBadFormats() {
        assertFalse(ApiKeyUtil.isValidFormat(null));
        assertFalse(ApiKeyUtil.isValidFormat(""));
        assertFalse(ApiKeyUtil.isValidFormat("sk-"));
        assertFalse(ApiKeyUtil.isValidFormat("sk-1234567890"));
        assertFalse(ApiKeyUtil.isValidFormat("sk-abcdefghijklmnopqrstuvwx!")); // '!' not allowed
        assertFalse(ApiKeyUtil.isValidFormat("xx-ABCDEFGHIJKLMNOPQRSTUVWX"));
    }

    @Test
    void acceptsCanonical() {
        assertTrue(ApiKeyUtil.isValidFormat("sk-ABCDEFGHIJKLMNOPQRSTUVWX"));
        assertTrue(ApiKeyUtil.isValidFormat("sk-1234567890ABCDEFGHIJKLMN"));
    }
}
