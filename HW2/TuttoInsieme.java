package HW2;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Base64;
import java.util.Scanner;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

public class TuttoInsieme {
    public static void main(String[] args) {

        try {
            // Generate key pairs for A and B
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair keyPairA = keyGen.generateKeyPair();
            KeyPair keyPairB = keyGen.generateKeyPair();

            // Create nonces
            SecureRandom random = new SecureRandom();
            byte[] nonce1 = new byte[16];
            byte[] nonce2 = new byte[16];
            random.nextBytes(nonce1);
            random.nextBytes(nonce2);

            // Debug prints for nonces
            System.out.println("Nonce1: " + Base64.getEncoder().encodeToString(nonce1));
            System.out.println("Nonce2: " + Base64.getEncoder().encodeToString(nonce2));

            // Shared memory (BlockingQueue) for communication
            BlockingQueue<byte[]> queueAtoB = new ArrayBlockingQueue<>(1);
            BlockingQueue<byte[]> queueBtoA = new ArrayBlockingQueue<>(1);

            // Thread A
            Thread threadA = new Thread(() -> {
                try {
                    // Encrypt message with B's public key
                    Cipher cipher = Cipher.getInstance("RSA");
                    cipher.init(Cipher.ENCRYPT_MODE, keyPairB.getPublic());
                    String messageA = "A:" + Base64.getEncoder().encodeToString(nonce1);
                    System.out.println("\nA prima di criptare: " + messageA);
                    byte[] encryptedMessageA = cipher.doFinal(messageA.getBytes());
                    System.out.println("A manda: " + Base64.getEncoder().encodeToString(encryptedMessageA));

                    // Send encrypted message to B
                    queueAtoB.put(encryptedMessageA);

                    // Receive encrypted response from B
                    byte[] encryptedMessageB = queueBtoA.take();

                    // Decrypt response from B with A's private key
                    cipher.init(Cipher.DECRYPT_MODE, keyPairA.getPrivate());
                    byte[] decryptedMessageB = cipher.doFinal(encryptedMessageB);
                    String responseB = new String(decryptedMessageB);
                    System.out.println("\nA riceve criptato: " + Base64.getEncoder().encodeToString(encryptedMessageB));
                    System.out.println("A riceve decriptato: " + responseB);

                    // Extract nonce2 from response and encrypt it with B's public key
                    String[] parts = responseB.split(":");
                    if (parts.length == 2 && parts[0].equals(Base64.getEncoder().encodeToString(nonce1))) {
                        System.out.println("\nA verifica nonce1: " + parts[0]);
                        System.out.println("A verifica nonce2: " + parts[1]);
                        cipher.init(Cipher.ENCRYPT_MODE, keyPairB.getPublic());
                        byte[] encryptedMessageA2 = cipher.doFinal(parts[1].getBytes());
                        System.out.println("\nA prima di criptare: " + parts[1]);
                        System.out.println("A manda: " + Base64.getEncoder().encodeToString(encryptedMessageA2));
                        queueAtoB.put(encryptedMessageA2);
                    }

                    // Receive confirmation from B
                    byte[] encryptedConfirmation = queueBtoA.take();
                    cipher.init(Cipher.DECRYPT_MODE, keyPairA.getPrivate());
                    byte[] decryptedConfirmation = cipher.doFinal(encryptedConfirmation);
                    String confirmation = new String(decryptedConfirmation);
                    System.out.println("\nA riceve conferma criptato: " + Base64.getEncoder().encodeToString(encryptedConfirmation));
                    System.out.println("A riceve conferma decriptato: " + confirmation);

                    // Generate Session key
                    KeyGenerator SessionKeyGen = KeyGenerator.getInstance("AES");
                    SessionKeyGen.init(128); // Key size
                    SecretKey secretKey = SessionKeyGen.generateKey();
                    System.out.println("\nChiave segreta generata: " + Base64.getEncoder().encodeToString(secretKey.getEncoded()));
                    // Send Session key
                    cipher.init(Cipher.ENCRYPT_MODE, keyPairB.getPublic());
                    System.out.println("\nA prima di criptare: " + Base64.getEncoder().encodeToString(secretKey.getEncoded()));
                    byte[] encryptedMessageA3 = cipher.doFinal(Base64.getEncoder().encodeToString(secretKey.getEncoded()).getBytes());
                    System.out.println("A manda: " + Base64.getEncoder().encodeToString(encryptedMessageA3));
                    queueAtoB.put(encryptedMessageA3);

                    // Take input from keyboard
                    Scanner scanner = new Scanner(System.in);
                    System.out.print("Enter message to send to B: ");
                    String userMessage = scanner.nextLine();

                    // Encrypt the message with the session key
                    cipher = Cipher.getInstance("AES");
                    cipher.init(Cipher.ENCRYPT_MODE, secretKey);
                    byte[] encryptedUserMessage = cipher.doFinal(userMessage.getBytes());
                    System.out.println("A manda messaggio criptato: " + Base64.getEncoder().encodeToString(encryptedUserMessage));
                    queueAtoB.put(encryptedUserMessage);

                } catch (Exception e) {
                    e.printStackTrace();
                }
            });

            // Thread B
            Thread threadB = new Thread(() -> {
                try {
                    // Receive encrypted message from A
                    byte[] encryptedMessageA = queueAtoB.take();

                    // Decrypt message from A with B's private key
                    Cipher cipher = Cipher.getInstance("RSA");
                    cipher.init(Cipher.DECRYPT_MODE, keyPairB.getPrivate());
                    byte[] decryptedMessageA = cipher.doFinal(encryptedMessageA);
                    String messageA = new String(decryptedMessageA);
                    System.out.println("\nB riceve criptato: " + Base64.getEncoder().encodeToString(encryptedMessageA));
                    System.out.println("B riceve decriptato: " + messageA);

                    // Extract nonce1 and create response with nonce1 and nonce2
                    String[] parts = messageA.split(":");
                    if (parts.length == 2 && parts[0].equals("A")) {
                        System.out.println("\nB verifica nonce1: " + parts[1]);
                        String responseB = Base64.getEncoder().encodeToString(nonce1) + ":" + Base64.getEncoder().encodeToString(nonce2);
                        System.out.println("B prima di criptare: " + responseB);
                        cipher.init(Cipher.ENCRYPT_MODE, keyPairA.getPublic());
                        byte[] encryptedMessageB = cipher.doFinal(responseB.getBytes());
                        System.out.println("B manda: " + Base64.getEncoder().encodeToString(encryptedMessageB));

                        // Send encrypted response to A
                        queueBtoA.put(encryptedMessageB);
                    }

                    // Receive encrypted nonce2 from A
                    byte[] encryptedMessageA2 = queueAtoB.take();
                    cipher.init(Cipher.DECRYPT_MODE, keyPairB.getPrivate());
                    byte[] decryptedMessageA2 = cipher.doFinal(encryptedMessageA2);
                    String messageA2 = new String(decryptedMessageA2);
                    System.out.println("\nB riceve criptato: " + Base64.getEncoder().encodeToString(encryptedMessageA2));
                    System.out.println("B riceve decriptato: " + messageA2);

                    // Send confirmation to A
                    cipher.init(Cipher.ENCRYPT_MODE, keyPairA.getPublic());
                    byte[] encryptedConfirmation = cipher.doFinal("CONFIRMED".getBytes());
                    System.out.println("B manda conferma: " + Base64.getEncoder().encodeToString(encryptedConfirmation));
                    queueBtoA.put(encryptedConfirmation);

                    // Receive encrypted message from A
                    byte[] encryptedMessageA3 = queueAtoB.take();
                    // Decrypt message from A with B's private key
                    cipher.init(Cipher.DECRYPT_MODE, keyPairB.getPrivate());
                    byte[] decryptedMessageA3 = cipher.doFinal(encryptedMessageA3);
                    String messageA3 = new String(decryptedMessageA3);
                    System.out.println("\nB riceve criptato: " + Base64.getEncoder().encodeToString(encryptedMessageA3));
                    System.out.println("B riceve decriptato: " + messageA3);

                    // Receive encrypted user message from A
                    byte[] encryptedUserMessage = queueAtoB.take();
                    cipher = Cipher.getInstance("AES");
                    cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(Base64.getDecoder().decode(messageA3), "AES"));
                    byte[] decryptedUserMessage = cipher.doFinal(encryptedUserMessage);
                    String userMessage = new String(decryptedUserMessage);
                    System.out.println("\nB riceve messaggio criptato: " + Base64.getEncoder().encodeToString(encryptedUserMessage));
                    System.out.println("B riceve messaggio decriptato: " + userMessage);

                } catch (Exception e) {
                    e.printStackTrace();
                }
            });

            // Start threads
            threadA.start();
            threadB.start();

            // Wait for threads to finish
            threadA.join();
            threadB.join();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
