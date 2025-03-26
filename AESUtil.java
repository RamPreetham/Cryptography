import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.security.SecureRandom;

public class AESUtil {

    private static final String AES = "AES";
    private static final String AES_GCM_NOPADDING = "AES/GCM/NoPadding";
    private static final int AES_KEY_SIZE = 256; // 256 bits
    private static final int IV_SIZE = 12;       // 96 bits for GCM
    private static final int TAG_LENGTH_BIT = 128;

    // Generate a random AES key
    public static SecretKey generateKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(AES);
        keyGen.init(AES_KEY_SIZE);
        return keyGen.generateKey();
    }

    // Encrypts a plain text using AES GCM
    public static String encrypt(String plainText, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_GCM_NOPADDING);
        GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        byte[] cipherText = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(cipherText);
    }

    // Decrypts the cipher text
    public static String decrypt(String cipherText, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_GCM_NOPADDING);
        GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        byte[] decoded = Base64.getDecoder().decode(cipherText);
        byte[] plainText = cipher.doFinal(decoded);
        return new String(plainText);
    }

    public static void main(String[] args) throws Exception {
        String original = "AccountNo: 123456789 | Amount: $1000";

        // Key and IV setup
        SecretKey key = generateKey();
        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);  // Secure random IV

        // Encrypt
        String encrypted = encrypt(original, key, iv);
        System.out.println("Encrypted: " + encrypted);

        // Decrypt
        String decrypted = decrypt(encrypted, key, iv);
        System.out.println("Decrypted: " + decrypted);
    }
}
