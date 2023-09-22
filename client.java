import java.io.*;
import java.net.*;

public class client {
    public static void main(String[] args) {
        try {
            Socket socket = new Socket("localhost", 12345);
            System.out.println("Connected to server...");

            // Create input and output streams for communication
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

            // Read user input and send it to the server
            BufferedReader userInput = new BufferedReader(new InputStreamReader(System.in));
            String message;

            while (true) {
                System.out.print("Enter a message to send to the server (or 'exit' to quit): ");
                message = userInput.readLine();

                if (message.equalsIgnoreCase("exit")) {
                    break;
                }

                // Send the message to the server
                out.println(message);

                // Receive and print the server's response
                String serverResponse = in.readLine();
                System.out.println("Server response: " + serverResponse);
            }

            // Close the connections
            in.close();
            out.close();
            userInput.close();
            socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
