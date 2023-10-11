import java.io.*;
import java.net.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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

    // Define the HashMap to store public keys as base64 strings
    public static Map<String, String> clientPublicKeys = new HashMap<>();

    public ClientHandler(Socket clientSocket) {
        this.clientSocket = clientSocket;
        try {
            this.out = new PrintWriter(clientSocket.getOutputStream(), true);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void run() {
        try {
            BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            String message;

            while ((message = in.readLine()) != null) {
                // Check for "@key" prefix to store the key
                if (message.startsWith("@key:")) {
                    // Split the message to get the client name and encoded public key
                    String[] parts = message.split(":", 3);

                    if (parts.length == 3) {
                        String clientName = parts[1];
                        String encodedPublicKey = parts[2];

                        // Directly store the base64 encoded public key in the map
                        clientPublicKeys.put(clientName, encodedPublicKey);
                        System.out.println("Stored public key for client: " + clientName + ":" + clientPublicKeys.get("Eli"));
                    } else {
                        System.out.println("Invalid key message format");
                    }
                }
                // Check for "@getKey" request
                else if (message.startsWith("@getKey:")) {
                    String[] parts = message.split(":", 2);
                    if (parts.length == 2) {
                        String requestedClientName = parts[1];
                        String requestedPublicKey = clientPublicKeys.get(requestedClientName);

                        if (requestedPublicKey != null) {
                            // Send the already base64-encoded public key to the requesting client
                            out.println("@keyResponse:" + requestedClientName + ":" + requestedPublicKey);

                            System.out.println("@keyResponse:" + requestedClientName + ":" + requestedPublicKey);

                        } else {
                            // Optionally handle the case where the requested public key doesn't exist
                            out.println("Error: Public key for " + requestedClientName + " not found.");
                        }
                    }
                } else {
                    // Handle as a regular message
                    server.broadcastMessage(message);
                }
            }

            // Close the connections
            in.close();
            clientSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
