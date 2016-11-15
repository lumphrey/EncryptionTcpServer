import java.io.*;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;

/**
 *
 */
public class EncryptionTcpServer {

    private static int mPort = -1;
    private static int mTotalSchemes = -1;

    //for use in Diffie-Hellman key exchange
    private static int mG = 5; //base
    private static int mP = 23; //modulus
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

        mSecretKey = testComputeSecret();
        System.out.println("Secret computed: " + mSecretKey);

        //initialization
        extractArgs(args);
        initializeServer();
        listen();
        initalizeStreams();


        //wait for client's "special number", needed to calculate secret key
        String message = waitForUnencryptedMessage();
        int clientNum = -1;
        try {
            clientNum = Integer.parseInt(message);
            System.out.println("Received integer " + clientNum + " from client. Calculating key...");
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

        //send server's "special number" to client
        int serverNum = (int) (Math.pow(mG, mLocalSecret) % mP);
        System.out.println("Sending int " + serverNum + " to client...");
        sendUnencryptedMessage(Integer.toString(serverNum));

        //wait for "ready" message from client before starting secure transfers


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
     * Blocks until a message is read from the input stream.
     * @return A String without line-termination characters.
     */
    private static String waitForUnencryptedMessage() {
        String message = null;

        while(true) {
            System.out.println("Waiting for message...");
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
