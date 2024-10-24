package HW2;
import java.security.*;
import java.util.Base64;

public class RSASignature {
    public static void main(String[] args) throws Exception {
        // Generate a pair of RSA keys (public and private)
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048); // Key size (2048-bit is common for RSA)
        KeyPair keyPair = keyGen.generateKeyPair();
        
        // Print the public and private keys (Base64 encoded)
        System.out.println("Public Key: " + Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
        System.out.println("Private Key: " + Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));

        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // Original message to be signed
        java.util.Scanner scanner = new java.util.Scanner(System.in);
        System.out.print("Scrivi qualcosa da firmare con RSA+SHA256: ");
        String message = scanner.nextLine();
        scanner.close();

        // Sign the message with the private key
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        byte[] signatureBytes = signature.sign();
        String signatureString = Base64.getEncoder().encodeToString(signatureBytes);
        System.out.println("Firma: " + signatureString);

        // Verifying the signature with the public key
        signature.initVerify(publicKey);
        signature.update(message.getBytes());
        boolean isVerified = signature.verify(signatureBytes);
        System.out.println("Verifica firma: " + isVerified);
    }
}
