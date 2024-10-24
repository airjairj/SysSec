package HW2;
import java.security.*;
import javax.crypto.Cipher;

import java.util.Base64;

public class RSACrypto {
    public static void main(String[] args) throws Exception {
        // Generate a pair of RSA keys (public and private)
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048); // Key size (2048-bit is common for RSA)
        KeyPair keyPair = keyGen.generateKeyPair();;
        // Print the public and private keys
        System.out.println("Public Key: " + Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
        System.out.println("Private Key: " + Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));


        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // Original message
        java.util.Scanner scanner = new java.util.Scanner(System.in);
        System.out.print("Scrivi qualcosa da criptare con RSA: ");
        String originalMessage = scanner.nextLine();
        scanner.close();

        // Encrypt the message using the public key
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = encryptCipher.doFinal(originalMessage.getBytes());

        // Encode the encrypted bytes to Base64 for easy display
        String encryptedMessage = Base64.getEncoder().encodeToString(encryptedBytes);
        System.out.println("Encrypted Message: " + encryptedMessage);

        // Decrypt the message using the private key
        Cipher decryptCipher = Cipher.getInstance("RSA");
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = decryptCipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
        String decryptedMessage = new String(decryptedBytes);

        // Display the decrypted message
        System.out.println("Decrypted Message: " + decryptedMessage);
    }
}
