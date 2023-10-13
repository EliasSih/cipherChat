import javax.crypto.Cipher;
import java.security.*;
import java.util.Base64;

public class RSA_encryption {

    private static final String RSA_MODE = "RSA/ECB/PKCS1Padding";
    private static final String ENCODING = "UTF-8";

    /**
     * Encrypts the given parameters using the provided public key.
     *
     * @param messageHash       The hash of the message.
     * @param encryptedMessage  The encrypted message in Base64 format.
     * @param secretKey         The AES secret key as a string.
     * @param publicKey         The RSA public key for encryption.
     * @return                  The encrypted result in Base64 format.
     * @throws Exception
     */
    public static String encrypt(String messageHash, String encryptedMessage, String secretKey, PublicKey publicKey) throws Exception {
        String combinedMessage = messageHash + ":" + encryptedMessage + ":" + secretKey;
        Cipher rsaCipher = Cipher.getInstance(RSA_MODE);
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = rsaCipher.doFinal(combinedMessage.getBytes(ENCODING));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    /**
     * Decrypts the given Base64 encoded encrypted message using the provided private key.
     *
     * @param encryptedBase64Message   The Base64 encoded encrypted message.
     * @param privateKey               The RSA private key for decryption.
     * @return                         The decrypted message in the format "hash:encrypted_message:secretKey".
     * @throws Exception
     */
    public static String decrypt(String encryptedBase64Message, PrivateKey privateKey) throws Exception {
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedBase64Message);
        Cipher rsaCipher = Cipher.getInstance(RSA_MODE);
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = rsaCipher.doFinal(decodedBytes);
        return new String(decryptedBytes, ENCODING);
    }

    /**
     * Encrypts the secret key using the provided public key, then concatenates the messageHash, encryptedMessage,
     * and the encrypted secret key.
     *
     * @param messageHash       The hash of the message.
     * @param encryptedMessage  The encrypted message in Base64 format.
     * @param secretKey         The secret key as a string.
     * @param publicKey         The RSA public key for encryption.
     * @return                  The result in Base64 format.
     * @throws Exception
     */
    public static String encryptKeyNotLoad(String messageHash, String encryptedMessage, String secretKey, PublicKey publicKey) throws Exception {
        Cipher rsaCipher = Cipher.getInstance(RSA_MODE);
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedSecretKeyBytes = rsaCipher.doFinal(secretKey.getBytes(ENCODING));
        String encryptedSecretKey = Base64.getEncoder().encodeToString(encryptedSecretKeyBytes);
        return Base64.getEncoder().encodeToString((messageHash + ":" + encryptedMessage + ":" + encryptedSecretKey).getBytes(ENCODING));
    }

    /**
     * Decrypts the encrypted secret key from the provided payload using the provided private key,
     * then returns the messageHash, encryptedMessage, and the decrypted secret key.
     *
     * @param encryptedBase64Payload   The Base64 encoded payload.
     * @param privateKey               The RSA private key for decryption.
     * @return                         The decrypted payload in the format "hash:encrypted_message:decryptedSecretKey".
     * @throws Exception
     */
    public static String decryptKeyNotLoad(String encryptedBase64Payload, PrivateKey privateKey) throws Exception {
        String decodedPayload = new String(Base64.getDecoder().decode(encryptedBase64Payload), ENCODING);
        String[] parts = decodedPayload.split(":");
        if (parts.length != 3) {
            throw new IllegalArgumentException("Invalid encrypted payload format");
        }
        Cipher rsaCipher = Cipher.getInstance(RSA_MODE);
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedSecretKeyBytes = rsaCipher.doFinal(Base64.getDecoder().decode(parts[2]));
        String decryptedSecretKey = new String(decryptedSecretKeyBytes, ENCODING);
        return parts[0] + ":" + parts[1] + ":" + decryptedSecretKey;
    }

    public static void main(String[] args) throws Exception {
        // Generate an RSA key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // Test for the original encrypt and decrypt methods
        String hash = "exampleHash";  // Assuming a sample hash for demonstration
        String encryptedMessage = encrypt(hash, "someEncryptedMessageBase64", "someSecretKey", keyPair.getPublic());
        System.out.println("Original Encrypted: " + encryptedMessage);

        String decryptedMessage = decrypt(encryptedMessage, keyPair.getPrivate());
        System.out.println("Original Decrypted: " + decryptedMessage);

        // Tests for the newer methods
        String encryptedPayload = encryptKeyNotLoad(hash, "sampleEncryptedMessageBase64", "sampleSecretKey", keyPair.getPublic());
        System.out.println("Encrypted Payload (Key Not Load): " + encryptedPayload);

        String decryptedPayload = decryptKeyNotLoad(encryptedPayload, keyPair.getPrivate());
        System.out.println("Decrypted Payload (Key Not Load): " + decryptedPayload);
    }

}
