import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;


public class server {
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
    public static void broadcastMessage(String message) {
        for (PrintWriter writer : clientWriters) {
            writer.println(message);
        }
    }
}

class ClientHandler implements Runnable {
    private Socket clientSocket;
    private PrintWriter out;

    public static Map<String, X509Certificate> clientCertificates = new HashMap<>();


    public ClientHandler(Socket clientSocket) {
        this.clientSocket = clientSocket;
        try {
            this.out = new PrintWriter(clientSocket.getOutputStream(), true);
        } catch (IOException e) {
            closeEverything(this.clientSocket, out);
        }
    }

    public void run() {
        try {
            BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            String message;

            while ((message = in.readLine()) != null) {
                // Check for "@key" prefix to store the key
                // generate the certificate here
                if (message.startsWith("@key:")) {
                    // Split the message to get the client name and encoded public key
                    String[] parts = message.split(":", 3);

                    if (parts.length == 3) {
                        String clientName = parts[1];
                        String encodedPublicKey = parts[2];
                        // generate the certificate
                        PublicKey publicKey = decodePublicKey(encodedPublicKey);
                        X509Certificate certificate = GenerateCertificate.issueCertificate(publicKey);

                        // Directly store the base64 encoded public key in the map
                        clientCertificates.put(clientName, certificate);
//                        clientPublicKeys.put(clientName, encodedPublicKey);
                        System.out.println("Stored certificate for client: " + clientName + ":" + clientCertificates.get(clientName));
                    } else {
                        System.out.println("Invalid key message format");
                    }
                }
                // Check for "@getKey" request
                // get certificate, verify it and then send it to the client
                else if (message.startsWith("@getKey:")) {
                    String[] parts = message.split(":", 2);
                    if (parts.length == 2) {
                        String requestedClientName = parts[1];
                        X509Certificate cert = clientCertificates.get(requestedClientName);

                        if (cert != null) {
                            if (GenerateCertificate.verifyCertificate(cert)) {
                                // Send the already base64-encoded public key to the requesting client
                                // get the certificate,
                                // get the public key from it
                                // and encode key
                                out.println("@keyResponse:" + requestedClientName + ":" + GenerateCertificate.encodeCertificate(cert));

                                System.out.println("@keyResponse:" + requestedClientName + ":" + GenerateCertificate.encodeCertificate(cert));
                            }
                            else {
                                out.println("Certificate not valid");
                            }
                        } else {
                            // Optionally handle the case where the requested public key doesn't exist
                            out.println("Err: Certificate for " + requestedClientName + " not found.");
                        }
                    }
                } else {
                    // Handle as a regular message
                    server.broadcastMessage(message);
                }
            }

            
            in.close();
            clientSocket.close();
        } catch (IOException e) {
            closeEverything(clientSocket, out);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public String encodedPublicKey(PublicKey publicKey) throws Exception {

        byte[] publicKeyBytes = publicKey.getEncoded();
        String EncodedPublicKey = Base64.getEncoder().encodeToString(publicKeyBytes);
        return EncodedPublicKey;
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
