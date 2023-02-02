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

        // setting the BufferReader we work with
        BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));

        // User decision of seeing encrypted messages
        System.out.println("Do you want to see the encrypted messages? Y/N");
        Boolean Debug = (stdIn.readLine().equals("Y"));

        // Connect to the server
        Socket socket = new Socket(HOST, PORT);
        System.out.println("Connected to chat server");

        //Set an RSA key pair to each client
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        // Start a new thread to listen for incoming messages
        ChatClientThread t1 = new ChatClientThread(socket,publicKey,privateKey,Debug);
        t1.start();

        // Read messages from the user and send them to the server
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
        String userInput;

        // Block until we have server public key
        while(t1.getServerPublicKey() == null){
        }

        // Create a cipher object (will be used to encode the message)
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE , t1.getServerPublicKey());


        // Sending the client public key and modules to the server
        String publicKeyStr = publicKey.toString();
        String[] arr = publicKeyStr.split("\n");
        String modulusStr = arr[2];
        out.println(modulusStr);
        String publicStr = arr[3];
        out.println(publicStr);

        // Get the client username
        System.out.println("What's your name?");
        String userName;
        userName = stdIn.readLine();

        //sending encrypted messages to the chat
        System.out.println("You can start message your friends:");
        while ((userInput = stdIn.readLine()) != null) {
            userInput = userName + ": "+ userInput;
            byte [] byteMessage = userInput.getBytes(StandardCharsets.UTF_8);
            byteMessage = encryptCipher.doFinal(byteMessage);
            BigInteger messageNum = new BigInteger(byteMessage);
            out.println(messageNum);
        }
    }
}

class ChatClientThread extends Thread {
    private Socket socket;
    private BufferedReader in;

    private PublicKey clientPublicKey;

    private PrivateKey clientPrivateKey;

    private PublicKey serverPublicKey;

    private boolean Debug;


    public ChatClientThread(Socket socket, PublicKey publicKey, PrivateKey privateKey, boolean Debug) throws IOException {
        this.socket = socket;
        this.clientPublicKey = publicKey;
        this.clientPrivateKey = privateKey;
        in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        this.Debug = Debug;
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
            BigInteger modulus = new BigInteger(in.readLine().substring(11));
            BigInteger pubExpo = new BigInteger(in.readLine().substring(19));

            // Recover the RSA key from string(server sent) to public key  object.
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus , pubExpo);
            serverPublicKey = keyFactory.generatePublic(keySpec);


            //create a cipher object in order to decrypt messages
            Cipher decryptCipher = Cipher.getInstance("RSA");
            decryptCipher.init(Cipher.DECRYPT_MODE , clientPrivateKey);



            //get messages
            while (true) {

                // Gets the message from the server
                 String rawMessage = in.readLine();

                // Handles bye message
                if(rawMessage.equals("BYE")){
                    break;
                }

                //decrypt the messages
                BigInteger messageBigNum = new BigInteger(rawMessage);
                if(Debug)
                    System.out.println("Received encrypted message:" + messageBigNum);
                byte[] decMessage = decryptCipher.doFinal(messageBigNum.toByteArray());
                if(Debug)
                    System.out.println("Message after decryption:" + new BigInteger(decMessage));
                String decMessageStr = new String(decMessage , StandardCharsets.UTF_8);

                if(decMessageStr == null){
                    continue;
                }
                //print the messages
                if(Debug)
                    decMessageStr = "Message Integer -> string decode: " + decMessageStr;
                System.out.println(decMessageStr);
            }
        } catch (IOException e) {
            System.out.println("Error in ChatClientThread: " + e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
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
                System.exit(0);
            } catch (IOException e) {
            }
        }
    }
}