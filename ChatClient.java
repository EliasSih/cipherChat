import javax.crypto.Cipher;
import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.net.*;
import javax.swing.text.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.awt.image.BufferedImage;
import javax.imageio.ImageIO;
import java.util.Random;


public class ChatClient {
    private BufferedReader in;
    private PrintWriter out;
    private JFrame frame = new JFrame("Secure Chat");
    private JTextField textField = new JTextField(40);
    private JTextPane textPane = new JTextPane();
    private DefaultStyledDocument doc = new DefaultStyledDocument();
    private String secretKey = "donotspeakAboutTHIS";
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private PublicKey receiverPublicKey;
    private String currentReceiver = null;
    private String lastReceiverName = null;
    private String userName;
    private Color userColor;
    private boolean textFieldEmpty = true;
    private final Object keyLock = new Object();
    private String latestMessage = null;

    private byte[] latestImage = null;



    public ChatClient(String serverAddress, int serverPort, String userName) {
        this.userName = userName;
        this.userColor = generateRandomColor();
        textPane.setDocument(doc);
        textPane.setEditable(false);
        frame.getContentPane().add(new JScrollPane(textPane), BorderLayout.CENTER);

        // Set a placeholder text for the text field
        setPlaceholderText();

        frame.getContentPane().add(textField, BorderLayout.SOUTH);

        JButton sendButton = new JButton("Send Message");
        JButton attachButton = new JButton("Send Image");
        JPanel buttonPanel = new JPanel(new FlowLayout());
        buttonPanel.add(sendButton);
        buttonPanel.add(attachButton);
        frame.getContentPane().add(buttonPanel, BorderLayout.NORTH);

        frame.pack();

        textField.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                sendMessage();
            }
        });

        sendButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                sendMessage();
            }
        });

        attachButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                attachImage();
            }
        });

        // Add a focus listener to handle the placeholder text
        textField.addFocusListener(new FocusListener() {
            public void focusGained(FocusEvent e) {
                if (textFieldEmpty) {
                    textField.setText("");
                    textField.setForeground(Color.BLACK);
                    textFieldEmpty = false;
                }
            }

            public void focusLost(FocusEvent e) {
                if (textField.getText().isEmpty()) {
                    setPlaceholderText();
                }
            }
        });

    }

    private void setPlaceholderText() {
        textField.setText("Type message here");
        textField.setForeground(Color.GRAY);
        textFieldEmpty = true;
    }

    private Color generateRandomColor() {
        Random rand = new Random();
        return new Color(rand.nextInt(256), rand.nextInt(256), rand.nextInt(256));
    }

    private void sendMessage() {

        String message = textField.getText();
        this.latestMessage = userName + ": " +message.replaceFirst("@[^:]+:", "");
        System.out.println("The latest: "+latestMessage);
        String encryptedMessage = AES_Enctyption.encrypt(userName + ": " + message, secretKey);

//        out.println("ENCRYPTED:" + encryptedMessage);
        textField.setText("");

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

            // hashing and encryption procedure
            String messageHash = hashing.HashString(message);
            String encryptedPayload = RSA_encryption.encrypt(messageHash, encryptedMessage, secretKey, receiverPublicKey);
            out.println("ENCRYPTED:" + encryptedPayload);
//            out.flush();

        } catch (Exception ex) {
            ex.printStackTrace();
        }


    }

    private void attachImage() {
        JFileChooser fileChooser = new JFileChooser();
        int result = fileChooser.showOpenDialog(frame);

        if (result == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
            try {
                BufferedImage image = ImageIO.read(selectedFile);
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                ImageIO.write(image, "PNG", baos);

                byte[] imageBytes = baos.toByteArray();
                latestImage = imageBytes;
                String encodedImage = Base64.getEncoder().encodeToString(imageBytes);
                String encryptedImage = AES_Enctyption.encrypt(encodedImage, secretKey);

                String imageHash = hashing.HashString(encodedImage);
                String encryptedImgPayload = RSA_encryption.encryptKeyNotLoad(imageHash, encryptedImage, secretKey, receiverPublicKey);

                out.println("IMAGE:" + encryptedImgPayload);

            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }
    }

    private void setUpNetworking(String serverAddress, int serverPort) throws IOException {
        Socket socket = new Socket(serverAddress, serverPort);
        in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        out = new PrintWriter(socket.getOutputStream(), true);
        System.out.println("connected to server...");
        System.out.println("connected to server...");

    }

    private void startReceivingMessages() {
        Thread readerThread = new Thread(new IncomingReader());
        readerThread.start();
    }

    private void setUpRsaKeys() throws NoSuchAlgorithmException {
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
    }

    // Inside the IncomingReader class
    class IncomingReader implements Runnable {

        private String decryptedMessage;

        private String decryptedImage;
        public void run() {
            try {
                while (true) {
                    String line = in.readLine();
                    if (line == null) {
                        break; // Server has closed the connection
                    }

                    String message = line;

                    try {
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
                        }
                    }
                    catch (Exception e) {
                        e.printStackTrace();
                    }



                    if (line.startsWith("ENCRYPTED:")) {

                        //first decrypt with public key
                        try {

                            message = message.replaceAll("ENCRYPTED:", "");

                            String partiallyDecrypted = RSA_encryption.decrypt(message, privateKey);

//                              extract the private key here:
                            String [] payload = partiallyDecrypted.split(":");

                            decryptedMessage = AES_Enctyption.decrypt(payload[1], payload[2]);


                            System.out.println("Decrypted message: " + decryptedMessage);
                        } catch (Exception e) {
                            // If there's an error, just use the original message
                            e.printStackTrace();
                            System.out.println("Failed to decrypt");
                            decryptedMessage = null;

                            // latest message to front-end
                        }

                        // Handle encrypted messages
                        String encryptedMessage = line.substring("ENCRYPTED:".length());


                        SwingUtilities.invokeLater(new Runnable() {
                            public void run() {
                                SimpleAttributeSet attributes = new SimpleAttributeSet();
                                StyleConstants.setAlignment(attributes, StyleConstants.ALIGN_LEFT);
                                StyleConstants.setForeground(attributes, userColor);

                                try {

                                    if(decryptedMessage != null)
                                        doc.insertString(doc.getLength(), decryptedMessage.replaceFirst("@[^:]+:", "") + "\n", attributes);
                                    else
                                        doc.insertString(doc.getLength(), latestMessage + "\n", attributes);
                                        System.out.println("latest pushed to front-end:" + latestMessage);

                                } catch (BadLocationException e) {
                                    e.printStackTrace();
                                }
                            }
                        });
                    } else if (line.startsWith("IMAGE:")) {
                        // Handle image messages

                        String imagePayload = line;

                        try {

                            imagePayload = imagePayload.replaceAll("IMAGE:", "");

                            String RsaDecrypted = RSA_encryption.decryptKeyNotLoad(imagePayload, privateKey);

//                              extract the private key here:
                            String [] payloadComponents = RsaDecrypted.split(":");

                            decryptedImage = AES_Enctyption.decrypt(payloadComponents[1], payloadComponents[2]);


                            System.out.println("Decrypted message: " + decryptedImage);
                        } catch (Exception e) {
                            // If there's an error, just use the original message
                            e.printStackTrace();
                            System.out.println("Failed to decrypt");
                            decryptedImage = null;

                            // latest message to front-end
                        }

                        SwingUtilities.invokeLater(new Runnable() {
                            public void run() {
                                try {

                                    byte[] imageBytes;
                                    BufferedImage receivedImage;

                                    if(decryptedImage != null){
                                        imageBytes = Base64.getDecoder().decode(decryptedImage);
                                        receivedImage = ImageIO.read(new ByteArrayInputStream(imageBytes));
                                    }
                                    else {
                                        imageBytes = Base64.getDecoder().decode(latestImage);
                                        receivedImage = ImageIO.read(new ByteArrayInputStream(imageBytes));
                                    }

                                    // Define your desired maximum width and height
                                    int maxWidth = 400;
                                    int maxHeight = 400;

                                    // Calculate new dimensions while maintaining aspect ratio
                                    int newWidth, newHeight;
                                    if (receivedImage.getWidth() > receivedImage.getHeight()) {
                                        newWidth = maxWidth;
                                        newHeight = (maxWidth * receivedImage.getHeight()) / receivedImage.getWidth();
                                    } else {
                                        newHeight = maxHeight;
                                        newWidth = (maxHeight * receivedImage.getWidth()) / receivedImage.getHeight();
                                    }

                                    // Resize the image
                                    Image scaledImage = receivedImage.getScaledInstance(newWidth, newHeight, Image.SCALE_SMOOTH);
                                    BufferedImage resizedImage = new BufferedImage(newWidth, newHeight, BufferedImage.TYPE_INT_ARGB);
                                    Graphics2D g2d = resizedImage.createGraphics();
                                    g2d.drawImage(scaledImage, 0, 0, null);
                                    g2d.dispose();

                                    SimpleAttributeSet attributes = new SimpleAttributeSet();
                                    StyleConstants.setAlignment(attributes, StyleConstants.ALIGN_LEFT);
                                    StyleConstants.setForeground(attributes, userColor);

                                    doc.insertString(doc.getLength(), "\n", attributes);
                                    textPane.setCaretPosition(textPane.getDocument().getLength());
                                    textPane.insertIcon(new ImageIcon(resizedImage));
                                } catch (Exception ex) {
                                    ex.printStackTrace();

                                }
                            }
                        });
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public static void main(String[] args) {
        if (args.length != 3) {
            System.err.println("Usage: java ChatClient <server_address> <server_port> <username>");
            System.exit(1);
        }

        String serverAddress = args[0];
        int serverPort = Integer.parseInt(args[1]);
        String userName = args[2];

        ChatClient client = new ChatClient(serverAddress, serverPort, userName);
        client.frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        client.frame.setVisible(true);

        try {
            client.setUpNetworking(serverAddress, serverPort);
            client.startReceivingMessages();

            //send public key to server:
            client.setUpRsaKeys();

        } catch (IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
}
