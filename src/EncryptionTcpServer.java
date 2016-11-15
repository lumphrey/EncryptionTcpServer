import com.sun.corba.se.spi.activation.Server;
import com.sun.istack.internal.Nullable;

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
    private static int mLocalSecret = 6;
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

        mSecretKey = testComputerSecret();
        System.out.println("Secret computed: " + mSecretKey);

        //initialization
        extractArgs(args);
        initializeServer();
        listen();
        initalizeStreams();

        String message = waitForUnencryptedMessage();
        int clientNum = -1;
        try {
            clientNum = Integer.parseInt(message);
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



    }


    /**
     * Extracts command line arguments and assigns them to global variables.
     * @param args Argument array.
     */
    private static void extractArgs(String[] args) {

        if(args.length < 2) {
            System.out.println("Incorrect number of parameters. Required: port, total number of security schemes.");
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
            try {
                message = mReader.readLine();
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
     * Calculates a secret key given a special number from the client.
     * @param clientNum An integer received from the client on connection.
     * @return
     */
    private static int calculateSecret(double clientNum) {
        int secret = -1;

        secret = (int) (Math.pow(clientNum, (double)mLocalSecret) % mP);

        return secret;
    }


    private static int testComputerSecret() {
        int secret = -1;

        secret = (int) (Math.pow(19, mLocalSecret) % mP);

        return secret;
    }




}
