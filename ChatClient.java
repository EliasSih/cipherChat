import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.net.*;
import javax.swing.text.*;
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
    
    public ChatClient(String serverAddress, int serverPort, String userName) {
        this.userName = userName;
        this.userColor = generateRandomColor();
        textPane.setDocument(doc);
        textPane.setEditable(false);
        frame.getContentPane().add(new JScrollPane(textPane), BorderLayout.CENTER);
        frame.getContentPane().add(textField, BorderLayout.SOUTH);
        frame.pack();

        textField.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                try {
                    String message = textField.getText();
                    sendMessage(message);
                    textField.setText("");
                } catch (IOException ex) {
                    ex.printStackTrace();
                }
            }
        });
    }
    
    private Color generateRandomColor() {
        Random rand = new Random();
        return new Color(rand.nextInt(256), rand.nextInt(256), rand.nextInt(256));
    }

    private void sendMessage(String message) throws IOException {
        String encryptedMessage = AES_Enctyption.encrypt(userName + ": " + message, secretKey);
        out.println(encryptedMessage);
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

    class IncomingReader implements Runnable {
        public void run() {
            try {
                while (true) {
                    String encryptedMessage = in.readLine();
                    if (encryptedMessage == null) {
                        break; // Server has closed the connection
                    }

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
