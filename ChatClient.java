import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.net.*;
import javax.swing.text.*;
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
    private String userName;
    private Color userColor;
    private boolean textFieldEmpty = true;

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
        String encryptedMessage = AES_Enctyption.encrypt(userName + ": " + message, secretKey);
        out.println("ENCRYPTED:" + encryptedMessage);
        textField.setText("");
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
                String encodedImage = Base64.getEncoder().encodeToString(imageBytes);
                String encryptedImage = AES_Enctyption.encrypt(encodedImage, secretKey);

                out.println("IMAGE:" + encryptedImage);
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }
    }

    private void setUpNetworking(String serverAddress, int serverPort) throws IOException {
        Socket socket = new Socket(serverAddress, serverPort);
        in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        out = new PrintWriter(socket.getOutputStream(), true);
        System.out.println("Connected to server...");
    }

    private void startReceivingMessages() {
        Thread readerThread = new Thread(new IncomingReader());
        readerThread.start();
    }

    // Inside the IncomingReader class
    class IncomingReader implements Runnable {
        public void run() {
            try {
                while (true) {
                    String line = in.readLine();
                    if (line == null) {
                        break; // Server has closed the connection
                    }

                    if (line.startsWith("ENCRYPTED:")) {
                        // Handle encrypted messages
                        String encryptedMessage = line.substring("ENCRYPTED:".length());
                        String decryptedMessage = AES_Enctyption.decrypt(encryptedMessage, secretKey);

                        SwingUtilities.invokeLater(new Runnable() {
                            public void run() {
                                SimpleAttributeSet attributes = new SimpleAttributeSet();
                                StyleConstants.setAlignment(attributes, StyleConstants.ALIGN_LEFT);
                                StyleConstants.setForeground(attributes, userColor);

                                try {
                                    doc.insertString(doc.getLength(), decryptedMessage + "\n", attributes);
                                } catch (BadLocationException e) {
                                    e.printStackTrace();
                                }
                            }
                        });
                    } else if (line.startsWith("IMAGE:")) {
                        // Handle image messages
                        String encryptedImage = line.substring("IMAGE:".length());
                        String decryptedImage = AES_Enctyption.decrypt(encryptedImage, secretKey);

                        SwingUtilities.invokeLater(new Runnable() {
                            public void run() {
                                try {
                                    byte[] imageBytes = Base64.getDecoder().decode(decryptedImage);
                                    BufferedImage receivedImage = ImageIO.read(new ByteArrayInputStream(imageBytes));

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
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
