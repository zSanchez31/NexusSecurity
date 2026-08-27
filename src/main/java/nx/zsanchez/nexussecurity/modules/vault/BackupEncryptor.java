package nx.zsanchez.nexussecurity.modules.vault;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.security.spec.KeySpec;

/**
 * AES-256-GCM encryption utility for securing server backups.
 */
public class BackupEncryptor {

    private static final int KEY_LENGTH = 256;
    private static final int ITERATION_COUNT = 65536;
    private static final int GCM_TAG_LENGTH = 128;
    private static final int IV_LENGTH = 12;
    private static final int SALT_LENGTH = 16;

    /**
     * Encrypts an input stream to an output stream using AES-256-GCM.
     */
    public static void encrypt(InputStream in, OutputStream out, String password) throws Exception {
        byte[] salt = new byte[SALT_LENGTH];
        byte[] iv = new byte[IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(salt);
        random.nextBytes(iv);

        // Write salt and IV header
        out.write(salt);
        out.write(iv);

        SecretKey key = deriveKey(password, salt);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH, iv));

        byte[] buffer = new byte[8192];
        int read;
        while ((read = in.read(buffer)) != -1) {
            byte[] output = cipher.update(buffer, 0, read);
            if (output != null) out.write(output);
        }
        byte[] finalBytes = cipher.doFinal();
        if (finalBytes != null) out.write(finalBytes);
    }

    /**
     * Decrypts an encrypted backup stream using AES-256-GCM.
     */
    public static void decrypt(InputStream in, OutputStream out, String password) throws Exception {
        byte[] salt = new byte[SALT_LENGTH];
        byte[] iv = new byte[IV_LENGTH];

        if (in.readNBytes(salt, 0, SALT_LENGTH) != SALT_LENGTH ||
            in.readNBytes(iv, 0, IV_LENGTH) != IV_LENGTH) {
            throw new IllegalArgumentException("Invalid encrypted file header");
        }

        SecretKey key = deriveKey(password, salt);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH, iv));

        byte[] buffer = new byte[8192];
        int read;
        while ((read = in.read(buffer)) != -1) {
            byte[] output = cipher.update(buffer, 0, read);
            if (output != null) out.write(output);
        }
        byte[] finalBytes = cipher.doFinal();
        if (finalBytes != null) out.write(finalBytes);
    }

    private static SecretKey deriveKey(String password, byte[] salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATION_COUNT, KEY_LENGTH);
        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), "AES");
    }
}
