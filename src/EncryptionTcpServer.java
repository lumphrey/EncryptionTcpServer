import java.io.*;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Random;

/**
 *
 */
public class EncryptionTcpServer {

    private static boolean mDebug = true;

    private static int mPort = -1;
    private static int mTotalSchemes = -1;
    private static int mScheme = -1;

    private static SubstitutionCipher mSubCipher;
    private static TranspositionCipher mTransCipher;

    //for use in Diffie-Hellman key exchange
    private static int mG = 5; //base
    private static int mP = 23; //modulus, must be prime
    private static int mLocalSecret = 6; //TODO: randomize
    private static int mSecretKey;

    //sockets
    private static ServerSocket mServerSocket = null;
    private static Socket mClient = null;

    //stream readers and writers
    private static BufferedReader mReader = null;
    private static DataOutputStream mToClient = null;

    /**
     * @param args [port, total number of schemes (N)]
     */
    public static void main(String[] args) {

        //mSecretKey = testComputeSecret();
        //System.out.println("Secret computed: " + mSecretKey);

        //initialization
        extractArgs(args);
        //randomizeLocalSecret(); //TODO large numbers break the program
        initializeServer();
        listen();
        initalizeStreams();
        initializeCiphers();


        //wait for client's "special number", needed to calculate secret key
        String message = waitForUnencryptedMessage();
        int clientNum = -1;
        try {
            clientNum = Integer.parseInt(message);
            System.out.println("\n\n\nReceived integer " + clientNum + " from client. Calculating key...");
        }
        catch (NumberFormatException e) {
            System.out.println("Expected integer from client. Closing connection.");
            try {
                mClient.close();
            }
            catch (IOException f) {
                System.exit(-1);
            }
        }

        mSecretKey = calculateSecret(clientNum);
        System.out.println("Calculated secret key: " + mSecretKey);

        //determine scheme to use
        mScheme = mSecretKey % mTotalSchemes;

        System.out.println("Using security scheme " + mScheme);

        //send server's "special number" to client
        int serverNum = (int) (Math.pow(mG, mLocalSecret) % mP);
        System.out.println("Sending int " + serverNum + " to client...");
        sendUnencryptedMessage(Integer.toString(serverNum) + "\n");

        String encryptedMsgFromClient = "";
        while(true) {
            encryptedMsgFromClient = waitForEncryptedMessage();
            System.out.println("Decrypted message: " + encryptedMsgFromClient);

            if(encryptedMsgFromClient.equalsIgnoreCase("quit")) {
                break;
            }
        }

    }


    /**
     * Extracts command line arguments and assigns them to global variables.
     * @param args Argument array.
     */
    private static void extractArgs(String[] args) {

        if(args.length < 2) {
            System.out.println("Incorrect number of parameters. Required: destination host, port, total number of security schemes.");
            System.exit(-1);
        }

        try {
            mPort = Integer.parseInt(args[0]);
        }
        catch (NumberFormatException e) {
            System.out.println("Error parsing integer from first argument.");
            System.exit(-1);
        }

        try {
            mTotalSchemes = Integer.parseInt(args[1]);
        }
        catch (NumberFormatException e) {
            System.out.println("Error parsing integer from second argument.");
            System.exit(-1);
        }
    }

    /**
     * Starts the server.
     */
    private static void initializeServer() {
        try {
            mServerSocket = new ServerSocket(mPort);
            System.out.println("Server listening on port " + mPort);
        }
        catch (IOException e) {
            System.out.println("Error initializing server on port " + mPort);
            e.printStackTrace();
            System.exit(-1);
        }
    }


    /**
     * Listens for a connection. Blocks until a connection from a client is established.
     */
    private static void listen() {
        try {
            mClient = mServerSocket.accept();
            InetAddress clientAddress = mClient.getInetAddress();
            System.out.println("Client " + clientAddress.toString() + " connected.");
        }
        catch (IOException e) {
            System.out.println("Error accepting connection.");
            e.printStackTrace();
            System.exit(-1);
        }
    }


    /**
     * Randomizes the local secret.
     */
    private static void randomizeLocalSecret() {
        Random random = new Random();
        mLocalSecret = random.nextInt(14) + 1;
        System.out.println("Local secret chosen: " + mLocalSecret);
    }


    /**
     * Sets up input/output streams.
     */
    private static void initalizeStreams() {

        try {
            mToClient = new DataOutputStream(mClient.getOutputStream());
            System.out.println("IO streams initialized.");
        }
        catch (IOException e) {
            System.out.println("Error initializing output stream to client.");
            e.printStackTrace();
            System.exit(-1);
        }

        try {
            mReader = new BufferedReader(new InputStreamReader(mClient.getInputStream()));
        }
        catch (IOException e) {
            System.out.println("Error initializing input stream.");
            e.printStackTrace();
            System.exit(-1);
        }

    }

    /**
     * Initializes the ciphers.
     */
    private static void initializeCiphers() {
        mSubCipher = new SubstitutionCipher(mTotalSchemes);
        mTransCipher = new TranspositionCipher();

        if(mDebug) {
            mSubCipher.printPermutations();
        }
    }


    /**
     * Blocks until a message is read from the input stream.
     * @return A String without line-termination characters.
     */
    private static String waitForUnencryptedMessage() {
        String message = null;

        while(true) {
            System.out.println("Waiting for unencrypted message...");
            try {
                message = mReader.readLine();
                System.out.println("Message received: " + message);
            }
            catch (IOException e) {
                System.out.println("Error receiving message.");
                e.printStackTrace();
                System.exit(-1);
            }

            if(message != null) {
                break;
            }
        }

        return message;
    }

    /**
     * Waits for an encrypted message, then decrypts it.
     * @return Plaintext.
     */
    private static String waitForEncryptedMessage() {
        String message = null;

        while(true) {
            System.out.println("\n\nWaiting for encrypted message...");
            try {
                message = mReader.readLine();
                System.out.println("Received encrypted message from client: " + message);
            }
            catch (IOException e) {
                System.out.println("Error receiving encrypted message.");
                e.printStackTrace();
                System.exit(-1);
            }

            if(message != null) {
                break;
            }
        }


        String decrypted = decrypt(message);

        return decrypted;
    }


    private static String decrypt(String ciphertext) {

        System.out.println("Decrypting ciphertext: " + ciphertext);


        String subCiphertext = mTransCipher.decrypt(ciphertext, mScheme);

        System.out.println("Reversed transposition: " + subCiphertext);
        System.out.println("Applying reverse substitution...");

        String plaintext = mSubCipher.decrypt(subCiphertext, mScheme);

        return plaintext;
    }

    private static void sendUnencryptedMessage(String msg) {
        try {
            mToClient.writeBytes(msg);
        }
        catch (IOException e) {
            System.out.println("Error sending message to client.");
            e.printStackTrace();
            System.exit(-1);
        }
    }


    /**
     * Calculates a secret key given a special number from the client.
     * @param clientNum An integer received from the client on connection.
     * @return
     */
    private static int calculateSecret(double clientNum) {
        int secret = -1;

        secret = (int) (Math.pow(clientNum, mLocalSecret) % mP);

        return secret;
    }


    private static int testComputeSecret() {
        int secret = -1;

        secret = (int) (Math.pow(8, 15) % mP);

        return secret;
    }




}
