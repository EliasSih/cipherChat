package src;

import javax.swing.*;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultStyledDocument;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;

public class ChatClient {
    private BufferedReader in;
    private PrintWriter out;
    private String certificate;
    private JFrame frame = new JFrame("Secure Chat");
    private JTextField textField = new JTextField(40);
    private JTextPane textPane = new JTextPane();
    private DefaultStyledDocument doc = new DefaultStyledDocument();
    private String secretKey = "donotspeakAboutTHIS";
    private String userName;
    private Color userColor;
    
    public ChatClient(String serverAddress, int serverPort, String userName) {
        this.userName = userName;
        this.certificate = "";

        this.userColor = generateRandomColor();
        textPane.setDocument(doc);
        textPane.setEditable(false);
        frame.getContentPane().add(new JScrollPane(textPane), BorderLayout.CENTER);
        frame.getContentPane().add(textField, BorderLayout.SOUTH);
        frame.pack();

        textField.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                String message = textField.getText();
                sendMsgToCA(message);
                textField.setText("");
            }
        });
    }
    
    private Color generateRandomColor() {
        Random rand = new Random();
        return new Color(rand.nextInt(256), rand.nextInt(256), rand.nextInt(256));
    }

    /**
     * Send messages to the other client
     */
    private void sendMessage(String message) throws IOException {
        String encryptedMessage = AES_Enctyption.encrypt(userName + ": " + message, secretKey);
        out.println(encryptedMessage);
    }

    /**
     * send messages to the CA
     */
    private void sendMsgToCA(String messageToSend) {
        try {
            if (messageToSend.equals("generate")){
                out.println(messageToSend + " " + encodedPublicKey());
            }
            else if (messageToSend.equals("verify")){
                out.println(messageToSend + " " + certificate);
            }
            else {
                String encryptedMessage = AES_Enctyption.encrypt(userName + ": " + messageToSend, secretKey);
                out.println(encryptedMessage);
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    /**
     *  the public key for the CA
     */

    public PublicKey generatePublicKey() throws Exception{
        // Generate a subject's key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return keyPair.getPublic();
    }
    public String encodedPublicKey() throws Exception {

        PublicKey publicKey = generatePublicKey();
        byte[] publicKeyBytes = publicKey.getEncoded();
        String EncodedPublicKey = Base64.getEncoder().encodeToString(publicKeyBytes);
        return EncodedPublicKey;
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

    /**
     * Reads messages from the CA server
     */

    private void startReceivingCAMessages() {
        Thread readerThread = new Thread(new CAIncomingReader());
        readerThread.start();
    }
    class CAIncomingReader implements Runnable {
        public void run() {
            try {
                while (true) {
                    String msgFromChat = in.readLine();
                    if (msgFromChat == null) {
                        break; // Server has closed the connection
                    }
                    int spaceIndex = msgFromChat.indexOf(' ');
                    if (msgFromChat.substring(0,spaceIndex).equals("Certificate:")){

                        SwingUtilities.invokeLater(new Runnable() {
                            public void run() {
                                SimpleAttributeSet attributes = new SimpleAttributeSet();
                                StyleConstants.setAlignment(attributes, StyleConstants.ALIGN_LEFT);
                                StyleConstants.setForeground(attributes, userColor);

                                try {
                                    certificate = msgFromChat.substring(spaceIndex+1);
                                    X509Certificate cert = GenerateCertificate.decodeCertificate(certificate);

                                    doc.insertString(doc.getLength(), "Subject: " + cert.getSubjectDN().toString() + "\n", attributes);
                                    doc.insertString(doc.getLength(), "Issuer: " + cert.getIssuerDN().toString() + "\n", attributes);
                                    doc.insertString(doc.getLength(), "Serial Number: " + cert.getSerialNumber() + "\n", attributes);

                                    SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                                    doc.insertString(doc.getLength(), "Valid From: " + dateFormat.format(cert.getNotBefore()) + "\n", attributes);
                                    doc.insertString(doc.getLength(), "Valid To: " + dateFormat.format(cert.getNotAfter()) + "\n", attributes);

                                    doc.insertString(doc.getLength(), "\nPublic Key:\n" + cert.getPublicKey() + "\n", attributes);

                                } catch (BadLocationException e) {
                                    e.printStackTrace();
                                } catch (CertificateException e) {
                                    throw new RuntimeException(e);
                                }
                            }
                        });

                    }
                    else if (msgFromChat.substring(0,spaceIndex).equals("Verified:")){
                        SwingUtilities.invokeLater(new Runnable() {
                            public void run() {
                                SimpleAttributeSet attributes = new SimpleAttributeSet();
                                StyleConstants.setAlignment(attributes, StyleConstants.ALIGN_LEFT);
                                StyleConstants.setForeground(attributes, userColor);

                                try {
                                    doc.insertString(doc.getLength(), msgFromChat + "\n", attributes);

                                } catch (BadLocationException e) {
                                    e.printStackTrace();
                                }
                            }
                        });
                        break;
                    }
                    else {
                        SwingUtilities.invokeLater(new Runnable() {
                            public void run() {
                                SimpleAttributeSet attributes = new SimpleAttributeSet();
                                StyleConstants.setAlignment(attributes, StyleConstants.ALIGN_LEFT);
                                StyleConstants.setForeground(attributes, userColor);

                                try {
                                    doc.insertString(doc.getLength(), msgFromChat + "\n", attributes);

                                } catch (BadLocationException e) {
                                    e.printStackTrace();
                                }
                            }
                        });
                    }


                }
                startReceivingMessages();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public static void main(String[] args) {
//        if (args.length != 3) {
//            System.err.println("Usage: java ChatClient <server_address> <server_port> <username>");
//            System.exit(1);
//        }
        Scanner scan = new Scanner(System.in);
        // first ask for the authentication message
        System.out.println("Enter serverAddress: ");
        String serverAddress = scan.nextLine();
        System.out.println("Enter serverPort: ");
        int serverPort = scan.nextInt();
        System.out.println("Enter userName: ");
        String userName = scan.nextLine();

//        String serverAddress = args[0];
//        int serverPort = Integer.parseInt(args[1]);
//        String userName = args[2];

        ChatClient client = new ChatClient(serverAddress, serverPort, userName);
        client.frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        client.frame.setVisible(true);

        try {
            client.setUpNetworking(serverAddress, serverPort);
            client.startReceivingCAMessages();
//            client.startReceivingMessages();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
