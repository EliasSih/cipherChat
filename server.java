import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;

public class server {
    public static void main(String[] args) {
        try {
            ServerSocket serverSocket = new ServerSocket(12345);
            System.out.println("Server listening on port 12345...");

            while (true) {
                // Accept a client connection
                Socket clientSocket = serverSocket.accept();
                System.out.println("Client connected: " + clientSocket.getInetAddress());

                BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                String encodedImage = in.readLine();

                // Decode the Base64 string back to bytes
                byte[] imageBytes = Base64.getDecoder().decode(encodedImage);

                // Save the decoded image to a file
                saveImageToFile(imageBytes, "output_image.jpg"); 

                // Create a new thread to handle the client
                ClientHandler clientHandler = new ClientHandler(clientSocket);
                Thread thread = new Thread(clientHandler);
                thread.start();
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void saveImageToFile(byte[] imageBytes, String fileName) throws IOException {
        Path outputPath = Paths.get(fileName);
        Files.write(outputPath, imageBytes);
        System.out.println("Image saved to: " + fileName);
    }
}

class ClientHandler implements Runnable {
    private Socket clientSocket;

    public ClientHandler(Socket clientSocket) {
        this.clientSocket = clientSocket;
    }

    public void run() {
        try {
            // Create input and output streams for communication
            BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);

            // Read and print messages from the client
            String message;
            while ((message = in.readLine()) != "exit") {
                System.out.println("Received from client: " + message);

                // Send a response back to the client
                out.println(message);
            }

            // Close the connections
            in.close();
            out.close();
            clientSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
