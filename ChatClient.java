import javax.swing.*;
import javax.swing.text.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.net.*;
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

        textPane = new JTextPane();
        textPane.setEditable(false);
        doc = textPane.getStyledDocument();
        frame.add(new JScrollPane(textPane), BorderLayout.CENTER);

        textField = new JTextField();
        frame.add(textField, BorderLayout.SOUTH);

        textField.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                sendMessage(userName + ": " + textField.getText());
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

    private void sendMessage(String message) {
        try {
            out.println(message);
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
            } catch (IOException | BadLocationException e) {
                e.printStackTrace();
            }
        }
    }
}
