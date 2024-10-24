package HW2;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.Base64;

public class AESCrypto {
    public static void main(String[] args) throws Exception {
        // Generate a key for AES
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128); // Key size
        SecretKey secretKey = keyGen.generateKey();
        System.out.println("Chiave segreta generata: " + Base64.getEncoder().encodeToString(secretKey.getEncoded()));

        // Create Cipher instance for AES
        Cipher cipher = Cipher.getInstance("AES");

        // Encrypt data

        java.util.Scanner scanner = new java.util.Scanner(System.in);
        System.out.print("Scrivi qualcosa da criptare con AES: ");
        String originalData = scanner.nextLine();
        scanner.close();
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedData = cipher.doFinal(originalData.getBytes());

        // Encode to Base64 for easy display
        String encryptedString = Base64.getEncoder().encodeToString(encryptedData);
        System.out.println("Criptato: " + encryptedString);

        // Decrypt data
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedData = cipher.doFinal(Base64.getDecoder().decode(encryptedString));
        String decryptedString = new String(decryptedData);
        System.out.println("Decrriptato: " + decryptedString);
    }
}
