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
import java.util.*;
import java.security.*;

public class ChatServer {
    private static final int PORT = 9000;
    public static List<ChatThread> threads = new ArrayList<>();

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {

        // Set an RSA key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        ServerSocket serverSocket = new ServerSocket(PORT);
        System.out.println("Server listening on port " + PORT);


        while (true) {
            Socket socket = serverSocket.accept();
            System.out.println("New client connected");

            // Start a new thread for this client
            ChatThread t = new ChatThread(socket , publicKey , privateKey);
            threads.add(t);
            t.start();
        }
    }
}

class ChatThread extends Thread {
    private Socket socket;
    private BufferedReader in;
    private PrintWriter out;

    private PublicKey clientPublicKey; //The client public key.

    private PublicKey serverPublicKey;

    private PrivateKey serverPrivateKey;


    public ChatThread(Socket socket ,PublicKey key, PrivateKey privateKey) throws IOException {
        this.socket = socket;
        in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        out = new PrintWriter(socket.getOutputStream(), true);
        serverPublicKey = key;
        serverPrivateKey = privateKey;
    }

    public PublicKey getClientPublicKey() {
        return clientPublicKey;
    }

    public void run() {
        try {
            // Send a welcome message to the client
            out.println("Welcome to the chat server! Type 'BYE' to disconnect.");

            // Send the server public key.
            String publicKeyStr = serverPublicKey.toString();
            String [] arr = publicKeyStr.split("\n");
            out.println(arr[2]);
            out.println(arr[3]);

            // Create a cipher object (will be used to decode the message)
            Cipher decryptCipher = Cipher.getInstance("RSA");
            decryptCipher.init(Cipher.DECRYPT_MODE , serverPrivateKey);

            //get the client public key and modulus
            BigInteger clientModulus = new BigInteger(in.readLine().substring(11));
            BigInteger clientExpo = new BigInteger(in.readLine().substring(19));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(clientModulus,clientExpo);
            clientPublicKey = keyFactory.generatePublic(keySpec);

            // Create a cipher object (will be used to encode the message)
            Cipher encryptCipher = Cipher.getInstance("RSA");


            // Get client messages and broadcast them to all clients
            while (true) {
                BigInteger input = new BigInteger(in.readLine());
                System.out.println("encrypted message: " + input);
                byte [] decInput = decryptCipher.doFinal(input.toByteArray());
                System.out.println("derypted message:" + new BigInteger(decInput));
                String decInputStr = new String(decInput , StandardCharsets.UTF_8);


                if (decInputStr == null || decInputStr.substring(decInputStr.length() - 3).equals("BYE")) {
                    break;
                }

                for (ChatThread t : ChatServer.threads) {
                    encryptCipher.init(Cipher.ENCRYPT_MODE , t.getClientPublicKey());
                    byte [] byteMessage = decInputStr.getBytes(StandardCharsets.UTF_8);
                    byteMessage = encryptCipher.doFinal(byteMessage);
                    BigInteger messageNum = new BigInteger(byteMessage);
                    t.out.println(messageNum);
                }
            }
        } catch (IOException e) {
            System.out.println("Error in ChatThread: " + e.getMessage());
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        } finally {
            try {
                out.println("BYE");
                System.out.println("User disconnected");
                socket.close();
            } catch (IOException e) {
            }
            ChatServer.threads.remove(this);
        }
    }
}