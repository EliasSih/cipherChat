import javax.swing.*;
import javax.swing.text.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.security.*;
import java.util.Base64;
import javax.crypto.*;


public class ChatClient {
    private Socket socket;
    private BufferedReader in;
    private PrintWriter out;
    private String userName;

    private JFrame frame;
    private JTextField textField;
    private JTextPane textPane;
    private StyledDocument doc;

    private Map<String, Color> userColors = new HashMap<>(); // Mapping of usernames to colors

    //    key pair for RSA encryption:
    private PrivateKey privateKey;
    private PublicKey publicKey;

    private PublicKey receiverPublicKey;
    private final Object keyLock = new Object();

    private String lastReceiverName = null;



    public ChatClient(String serverAddress, int serverPort, String userName) {
        this.userName = userName;

        try {
            socket = new Socket(serverAddress, serverPort);
            System.out.println("Connected to server...");

            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            out = new PrintWriter(socket.getOutputStream(), true);

            // Generate a random color for this user
            Color userColor = getRandomColor();
            userColors.put(userName, userColor); // Store the color in the mapping

            createGUI();
            setupNetworking();

            //Generate private and public key
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair pair = keyGen.generateKeyPair();
            this.privateKey = pair.getPrivate();
            this.publicKey = pair.getPublic();
            System.out.println("public Key" + publicKey);

            // Send the public key to the server
            String encodedPublicKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());
            out.println("@key:" + userName + ":" + encodedPublicKey);

        } catch (IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    private void createGUI() {
        frame = new JFrame("Chat Client");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(400, 300);

        textPane = new JTextPane();
        textPane.setEditable(false);
        doc = textPane.getStyledDocument();
        frame.add(new JScrollPane(textPane), BorderLayout.CENTER);

        textField = new JTextField();
        frame.add(textField, BorderLayout.SOUTH);

        textField.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
//                sendMessage(userName + ": " + textField.getText());
                sendMessage(textField.getText());
                System.out.println("message by: @" + userName);
                textField.setText("");
            }
        });

        frame.setVisible(true);
    }

    private void setupNetworking() {
        try {
            Thread readerThread = new Thread(new IncomingReader());
            readerThread.start();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    // encrypt message with RSA and encode it  as a base64 string then push it to the port
    String currentReceiver = null;

    private void sendMessage(String message) {
        try {

            System.out.println("message:\n"+ message.trim());
            // Check if the message specifies a receiver with '@'
            if (message.trim().startsWith("@")) {
                int colonIndex = message.indexOf(":");
                if (colonIndex > 0) {
                    currentReceiver = message.substring(1, colonIndex); // Extract receiver name
                    lastReceiverName = currentReceiver; // Update last used receiver's name
                    message = message.substring(colonIndex + 1); // Strip out the receiver's name from the actual message
                }
            } else if (lastReceiverName != null) {
                currentReceiver = lastReceiverName;
            } else {
                System.out.println("Receiver's name not specified. Please specify a receiver's name using '@receiverName:MessageContent'.");
                return;
            }

            if (receiverPublicKey == null) {
                System.out.println("Receiver's public key not set. Requesting public key from the server.");

                // Send a request to the server to get the receiver's public key
                out.println("@getKey:" + currentReceiver);

                synchronized (keyLock) {
                    keyLock.wait();  // Block and wait until we get notified (when the key arrives)
                }
            }

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, receiverPublicKey);
            byte[] encryptedBytes = cipher.doFinal(message.getBytes());
            String encryptedMessage = Base64.getEncoder().encodeToString(encryptedBytes);
            out.println(encryptedMessage);
            out.flush();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }


    private Color getRandomColor() {
        Random rand = new Random();
        int r = rand.nextInt(256);
        int g = rand.nextInt(256);
        int b = rand.nextInt(256);
        return new Color(r, g, b);
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                if (args.length != 3) {
                    System.out.println("Usage: java ChatClient <Server_IP> <Server_Port> <User_Name>");
                    System.exit(1);
                }

                String serverAddress = args[0];
                int serverPort = Integer.parseInt(args[1]);
                String userName = args[2];

                new ChatClient(serverAddress, serverPort, userName);
            }
        });
    }

    class IncomingReader implements Runnable {
        public void run() {
            String message;
            try {
                while ((message = in.readLine()) != null) {
                    // Logging the incoming message for better debugging.
                    System.out.println("Received raw message: " + message);

                    // Handle key response from the server
                    if (message.startsWith("@keyResponse:")) {
                        String[] parts = message.split(":", 3);
                        if (parts.length == 3) {
                            String sender = parts[1];
                            String base64Key = parts[2];

                            if (sender.equals(currentReceiver)) {
                                byte[] decodedKey = Base64.getDecoder().decode(base64Key);
                                X509EncodedKeySpec spec = new X509EncodedKeySpec(decodedKey);
                                KeyFactory kf = KeyFactory.getInstance("RSA");
                                receiverPublicKey = kf.generatePublic(spec);

                                synchronized (keyLock) {
                                    keyLock.notify(); // Wake up any waiting threads
                                }

                                continue; // Move on to the next iteration, we don't want to display the key response
                            }
                        }
                    } else if (!message.startsWith("@getKey:")) { // Exclude any special commands here
                        // Try to decrypt the message
                        try {
                            byte[] encryptedBytes = Base64.getDecoder().decode(message);
                            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                            cipher.init(Cipher.DECRYPT_MODE, privateKey);
                            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
                            message = new String(decryptedBytes);
                            System.out.println("Decrypted message: " + message);
                        } catch (Exception e) {
                            // If there's an error, just use the original message
                            e.printStackTrace();
                            System.out.println("Failed to decrypt");
                        }
                    }

                    int colonIndex = message.indexOf(":");
                    if (colonIndex != -1 && colonIndex < message.length() - 1) {
                        String sender = message.substring(0, colonIndex).trim();
                        String content = message.substring(colonIndex + 1).trim();

                        // Determine the color based on the sender's name
                        Color color = userColors.get(sender);

                        // Set the color of the text
                        if (color != null) {
                            SimpleAttributeSet attributes = new SimpleAttributeSet();
                            StyleConstants.setForeground(attributes, color);
                            doc.insertString(doc.getLength(), message + "\n", attributes);
                        } else {
                            doc.insertString(doc.getLength(), message + "\n", null);
                        }
                    } else {
                        doc.insertString(doc.getLength(), message + "\n", null);
                    }
                }
            } catch (IOException | BadLocationException | GeneralSecurityException e) {
                e.printStackTrace();
            }
        }
    }

}