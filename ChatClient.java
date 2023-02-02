import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.security.*;

public class ChatClient {
    private static final String HOST = "localhost";
    private static final int PORT = 9000;

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Socket socket = new Socket(HOST, PORT);
        System.out.println("Connected to chat server");

        //Set a RSA key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // Start a new thread to listen for incoming messages
        ChatClientThread t1 = new ChatClientThread(socket);
        t1.start();

        // Read messages from the user and send them to the server
        BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
        String userInput;

        // Block until we have server public key
        while(t1.getServerPublicKey() == null){
        }
        System.out.println("Server public key: \n" + t1.getServerPublicKey());

        // Create a cipher object (will be used to encode the message)
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE , t1.getServerPublicKey());

        // Get userInput message -> byte [] -> BigInteger -> BigInteger^Exponent -> out socket.
        while ((userInput = stdIn.readLine()) != null) {
            byte [] byteMessage = userInput.getBytes(StandardCharsets.UTF_8);
            System.out.println("non ciphered: " + new BigInteger(byteMessage));
            byteMessage = encryptCipher.doFinal(byteMessage);
            BigInteger messageNum = new BigInteger(byteMessage);
            System.out.println("chiphered: " + messageNum);

            out.println(messageNum);  //ToDo turn the message to -> byte[] -> BigInteger -> ^Exponent and only then send it

        }
    }
}

class ChatClientThread extends Thread {
    private Socket socket;
    private BufferedReader in;

    private int publicKey;

    private int privateKey;

    private PublicKey serverPublicKey;

    public ChatClientThread(Socket socket) throws IOException {
        this.socket = socket;
        in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

    }

    public PublicKey getServerPublicKey() {
        return serverPublicKey;
    }

    public void run() {
        try {
            // Print incoming messages
            String message;

            //Welcome message:
            message = in.readLine();
            System.out.println(message);

            // Server public key - extract only the modulus and public exponent.
            message = in.readLine();
            System.out.println(message);
            message = in.readLine();
            System.out.println(message);
            BigInteger modulus = new BigInteger(in.readLine().substring(11));
            System.out.println(modulus);
            BigInteger pubExpo = new BigInteger(in.readLine().substring(19));
            System.out.println(pubExpo);

            // Recover the RSA key from string(server sent) to public key  object.
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus , pubExpo);
            serverPublicKey = keyFactory.generatePublic(keySpec);
//            System.out.println("Server public key: \n" + serverPublicKey);


            while ((message = in.readLine()) != null) {
                System.out.println(message);
            }
        } catch (IOException e) {
            System.out.println("Error in ChatClientThread: " + e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        } finally {
            try {
                socket.close();
            } catch (IOException e) {
            }
        }
    }
}