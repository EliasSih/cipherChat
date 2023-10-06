import javax.swing.*;
import javax.swing.text.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

public class ChatClient {
    private Socket socket;
    private BufferedReader in;
    private PrintWriter out;
    private String userName;

    private JFrame frame;
    private JTextField textField;
    private JTextPane textPane;
    private StyledDocument doc;

    private Map<String, Color> userColors = new HashMap<>(); // Mapping of user names to colors
    static File selectedFile;

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
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void createGUI() {
        frame = new JFrame("Chat Client");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(400, 300);

        JPanel inputPanel = new JPanel(new BorderLayout());

        textPane = new JTextPane();
        textPane.setEditable(false);
        doc = textPane.getStyledDocument();
    
        textField = new JTextField();
        inputPanel.add(textField, BorderLayout.CENTER);
    
        JButton selectImageButton = new JButton("Select Image");
        inputPanel.add(selectImageButton, BorderLayout.EAST);
    
        frame.add(new JScrollPane(textPane), BorderLayout.CENTER);
        frame.add(inputPanel, BorderLayout.SOUTH);

        textField.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                
                if (selectedFile != null) {
                    try {
                        Path imagePath = Path.of(selectedFile.getAbsolutePath()); 
                        byte[] imageBytes = Files.readAllBytes(imagePath);

                        // Encode the image as a Base64 string
                        String encodedImage = Base64.getEncoder().encodeToString(imageBytes);
                        String hashedImage = hashing.encryptThisString(encodedImage);
                        sendImage(encodedImage + " " + hashedImage);

                        String hashedMessage = hashing.encryptThisString(textField.getText());
                        sendMessage(userName + ": " + textField.getText() + " " + hashedMessage);                     
                    } catch (IOException error) {
                        error.printStackTrace();
                    }
                } else {
                    String hashedMessage = hashing.encryptThisString(textField.getText());
                    sendMessage(userName + ": " + textField.getText() + " " + hashedMessage);
                }
                textField.setText("");
            }
        });

        selectImageButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                JFileChooser fileChooser = new JFileChooser();
                int result = fileChooser.showOpenDialog(frame);
                if (result == JFileChooser.APPROVE_OPTION) {
                    selectedFile = fileChooser.getSelectedFile();
                    // Store the selected image file path (selectedFile.getAbsolutePath())                    
                }
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

    private void sendMessage(String message) {
        try {
            out.println(message);
            out.flush();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    private void sendImage(String image) {
        try {
            out.println(image);
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
                    int colonIndex = message.indexOf(":");
                    if (colonIndex != -1 && colonIndex < message.length() - 1) {
                        String sender = message.substring(0, colonIndex).trim();
                        String content = message.substring(colonIndex + 1).trim();

                        // Determine the color based on the sender's name
                        Color color = userColors.get(sender);

                        String[] parts = message.split(" ");

                        // Set the color of the text
                        if (color != null) {
                            SimpleAttributeSet attributes = new SimpleAttributeSet();
                            StyleConstants.setForeground(attributes, color);                           
                            doc.insertString(doc.getLength(), parts[0] + " " + parts[1] + "\n", attributes);
                            
                        } else {
                            doc.insertString(doc.getLength(), parts[0] + " " + parts[1] + "\n", null);
                        }

                        if (hashing.encryptThisString(parts[1]).equals(parts[2])) {
                                System.out.println("Hash Value for message is Valid");
                            } else {
                                System.out.println("Hash Value for message is Invalid");
                        }
                    } else {
                        doc.insertString(doc.getLength(), "New Image\n", null);

                        String[] parts = message.split(" ");

                        if (hashing.encryptThisString(parts[0]).equals(parts[1])) {
                                System.out.println("Hash Value for image is Valid");
                            } else {
                                System.out.println("Hash Value for image is Invalid");
                        }

                        // Decode the Base64 string back to bytes
                        byte[] imageBytes = Base64.getDecoder().decode(parts[0]);

                        // Save the decoded image to a file
                        saveImageToFile(imageBytes, "output_image.jpg"); 
                    }
                }
            } catch (IOException | BadLocationException e) {
                e.printStackTrace();
            }
        }

        private static void saveImageToFile(byte[] imageBytes, String fileName) throws IOException {
            Path outputPath = Paths.get(fileName);
            Files.write(outputPath, imageBytes);
            System.out.println("Image saved to: " + fileName);
        }
    }
}
