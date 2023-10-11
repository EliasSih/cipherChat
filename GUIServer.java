
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;



public class GUIServer {
    private static List<PrintWriter> clientWriters = new ArrayList<>();


    public static void main(String[] args) {
        try {
            ServerSocket serverSocket = new ServerSocket(12345);
            System.out.println("Server listening on port 12345...");

            while (true) {
                // Accept a client connection
                Socket clientSocket = serverSocket.accept();
                System.out.println("Client connected: " + clientSocket.getInetAddress());

                // Create a new thread to handle the client
                ClientHandler clientHandler = new ClientHandler(clientSocket);
                Thread thread = new Thread(clientHandler);
                thread.start();

                // Create a PrintWriter for this client and add it to the list
                PrintWriter clientWriter = new PrintWriter(clientSocket.getOutputStream(), true);
                clientWriters.add(clientWriter);
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // Helper method to broadcast a message to all connected clients
    public static void sendMessageToClient(String message) {
        for (PrintWriter writer : clientWriters) {
            writer.println(message);
        }
    }
}

class ClientHandler implements Runnable {
    private Socket clientSocket;
    private PrintWriter out;

    public ClientHandler(Socket clientSocket) {
        this.clientSocket = clientSocket;
        try {
            this.out = new PrintWriter(clientSocket.getOutputStream(), true);
        } catch (IOException e) {
            closeEverything(clientSocket, out);
        }
    }

    public void run() {
        try {
            BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            String messageFromClient;

            while ((messageFromClient = in.readLine()) != null) {
                System.out.println("Received from client: " + messageFromClient);

                // Broadcast the certificate to all connected clients
                if ((messageFromClient.contains(" ")) && (messageFromClient.substring(0,messageFromClient.indexOf(' ')).equals("generate"))){
                    String encodedPKey = messageFromClient.substring(messageFromClient.indexOf(' ')+1);
                    X509Certificate certificate = GenerateCertificate.issueCertificate(decodePublicKey(encodedPKey));
                    String cert = GenerateCertificate.encodeCertificate(certificate);
                    GUIServer.sendMessageToClient("Certificate: " + cert);
                }
                else if ((messageFromClient.contains(" ")) && (messageFromClient.substring(0,messageFromClient.indexOf(' ')).equals("verify"))){
                    String encodedCertificate = messageFromClient.substring(messageFromClient.indexOf(' ')+1);
                    X509Certificate verifyCert = GenerateCertificate.decodeCertificate(encodedCertificate);
                    boolean valid = GenerateCertificate.verifyCertificate(verifyCert);
                    messageFromClient = String.valueOf(valid);
                    if (valid){
                        GUIServer.sendMessageToClient("Verified: " + messageFromClient); }
                }
                // send chat messages to client
                else {
                    GUIServer.sendMessageToClient(messageFromClient);
                }


            }
            // Close the connections
            in.close();
            clientSocket.close();
        } catch (IOException e) {
            closeEverything(clientSocket, out);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public PublicKey decodePublicKey(String encodedPublicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // Decode the Base64-encoded public key into a byte array
        byte[] publicKeyBytes = Base64.getDecoder().decode(encodedPublicKey);

        // Create an X509EncodedKeySpec to represent the public key
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);

        // Get a KeyFactory for the desired algorithm (e.g., RSA or EC)
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);

        return publicKey;

    }

    public void closeEverything(Socket socket, PrintWriter writer) {
        try {
            if (writer != null) {
                writer.close();
            }
            if (socket != null) {
                socket.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
