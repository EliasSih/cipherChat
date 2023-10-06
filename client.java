import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Scanner;

public class client {
    public static void main(String[] args) {
        try {
            Socket socket = new Socket("localhost", 12345);
            System.out.println("Connected to server...");

            // Create input and output streams for communication
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

            // Read the image file
            Path imagePath = Path.of("gaming1.jpg"); 
            byte[] imageBytes = Files.readAllBytes(imagePath);

            // Encode the image as a Base64 string
            String encodedImage = Base64.getEncoder().encodeToString(imageBytes);
            System.out.println(encodedImage);

            // Send the encoded image to the server
            out.println(encodedImage);

            // Read user input and send it to the server
            Scanner scanner = new Scanner(System.in);
            String message;

            while (true) {
                System.out.print("Enter a message to send to the server (or 'exit' to quit): ");
                message = scanner.nextLine();

                if (message.equalsIgnoreCase("exit")) {
                    break;
                }

                //hashing hash = new hashing();
                // Hash the message using SHA-1
                String hashedMessage = hashing.encryptThisString(message);

                // Send both the original message and its hash to the server
                out.println("Original Message: " + message);
                out.println("Hashed Message: " + hashedMessage);

                // Receive and print the server's response
                String serverResponse = in.readLine();
                System.out.println("Server response: " + serverResponse);
            }

            out.println(message);
            scanner.close();
            socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
