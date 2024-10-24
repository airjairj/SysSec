package HW2;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class ShaHashing {
    public static void main(String[] args) {
        java.util.Scanner scanner = new java.util.Scanner(System.in);
        System.out.print("Scrivi qualcosa Hashare con SHA-256: ");
        String originalData = scanner.nextLine();
        scanner.close();
        
        try {
            // Create a MessageDigest instance for SHA-256
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            // Perform hashing
            byte[] hashBytes = digest.digest(originalData.getBytes());

            // Convert byte array to hexadecimal string
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0'); // Add leading zero if needed
                hexString.append(hex);
            }

            // Display the hashed value
            System.out.println("Stringa iniziale: " + originalData);
            System.out.println("Valore hashato (SHA-256): " + hexString.toString());
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Errore: " + e.getMessage());
        }
    }
}
