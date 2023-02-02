import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.security.*;

public class ChatServer {
    private static final int PORT = 9000;
    public static List<ChatThread> threads = new ArrayList<>();

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {

        // Set a RSA key pair
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

    private int publicKey; //The client public key.

    private PublicKey serverPublicKey;

    private PrivateKey serverPrivateKey;

    public ChatThread(Socket socket ,PublicKey key, PrivateKey privateKey) throws IOException {
        this.socket = socket;
        in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        out = new PrintWriter(socket.getOutputStream(), true);
        serverPublicKey = key;
        serverPrivateKey = privateKey;

    }

    public void run() {
        try {
            // Send a welcome message to the client
            out.println("Welcome to the chat server! Type 'BYE' to disconnect.");

            // Send the server public key.
            String publicKeyStr = serverPublicKey.toString();
            System.out.println(serverPublicKey.toString());
            String [] arr = publicKeyStr.split("\n");
            out.println(arr[0]);
            out.println(arr[1]);
            out.println(arr[2]);
            out.println(arr[3]);
//            System.out.println(serverPublicKey);
//            ObjectOutputStream obOut = new ObjectOutputStream(socket.getOutputStream());
//            obOut.writeObject(publicKey);

            // Create a cipher object (will be used to decode the message)
            Cipher decryptCipher = Cipher.getInstance("RSA");
            decryptCipher.init(Cipher.DECRYPT_MODE , serverPrivateKey);

            // Get client messages and broadcast them to all clients
            while (true) {
                BigInteger input = new BigInteger(in.readLine()); //String -> BigInteger.
                String decInput = new String(decryptCipher.doFinal(input.toByteArray()) , StandardCharsets.UTF_8);


                if (decInput == null || decInput.equals("BYE")) {
                    break;
                }
                for (ChatThread t : ChatServer.threads) {
                    t.out.println(decInput);
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
        } finally {
            try {
                socket.close();
            } catch (IOException e) {
            }
            ChatServer.threads.remove(this);
        }
    }
}