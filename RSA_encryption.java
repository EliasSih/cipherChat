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
        // Concatenate the given parameters
        String combinedMessage = messageHash + ":" + encryptedMessage + ":" + secretKey;

        // Initialize the RSA cipher in encrypt mode
        Cipher rsaCipher = Cipher.getInstance(RSA_MODE);
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);

        // Encrypt and then encode in Base64
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
        // Decode from Base64 and then decrypt
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedBase64Message);
        Cipher rsaCipher = Cipher.getInstance(RSA_MODE);
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = rsaCipher.doFinal(decodedBytes);

        return new String(decryptedBytes, ENCODING);
    }

    // Example usage (not part of the requirement, just for demonstration)
    public static void main(String[] args) throws Exception {
        // Generate an RSA key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        String hash = hashing.HashString("what is this");

        // Encrypt
        String encryptedMessage = encrypt(hash, "someEncryptedMessage", "someSecretKey", keyPair.getPublic());
        System.out.println("Encrypted: " + encryptedMessage);

        // Decrypt
        String decryptedMessage = decrypt(encryptedMessage, keyPair.getPrivate());
        System.out.println("Decrypted: " + decryptedMessage);
    }
}
