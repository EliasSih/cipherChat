package src;

import java.io.*;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Scanner;

public class Client {

    private Socket socket;
    private BufferedReader bufferedReader;
    private BufferedWriter bufferedWriter;
    private String username;
    private String certificate;

    public Client(Socket socket, String username) {
        try {
            this.socket = socket;
            this.bufferedWriter = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
            this.bufferedReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            this.username = username;
            this.certificate = "";
        } catch (IOException e) {
            closeEverything(socket, bufferedReader, bufferedWriter);
        }
    }

    public void sendMessage(){
        try {
            bufferedWriter.write(username);
            bufferedWriter.newLine();
            bufferedWriter.flush();

            Scanner scanner = new Scanner(System.in);
            while (socket.isConnected()){
                String messageToSend = scanner.nextLine();
                bufferedWriter.write(username + ": " + messageToSend);
                bufferedWriter.newLine();
                bufferedWriter.flush();
            }
        } catch (IOException e) {
            closeEverything(socket, bufferedReader, bufferedWriter);
        }
    }

    public void listenForMessage(){
        new Thread(new Runnable() {
            @Override
            public void run() {
                String msgFromChat;
                try {

                    msgFromChat = bufferedReader.readLine();
                    System.out.println(msgFromChat);
                } catch (IOException e){
                    closeEverything(socket, bufferedReader, bufferedWriter);
                }
                while (socket.isConnected()){
                    try {
                        msgFromChat = bufferedReader.readLine();
                        System.out.println(msgFromChat);
                    } catch (IOException e){
                        closeEverything(socket, bufferedReader, bufferedWriter);
                    }
                }
            }
        }).start();
    }

    /**
     * generate a KeyPair to send to the CA
     **/
    public PublicKey generatePublicKey() throws Exception{
        // Generate a subject's key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return keyPair.getPublic();
    }

    /**
     * Get the public key
     * Encode the public key as a byte array
     * Convert the byte array to a Base64 string
     */
    public String encodedPublicKey() throws Exception {

        PublicKey publicKey = generatePublicKey();
        byte[] publicKeyBytes = publicKey.getEncoded();
        String EncodedPublicKey = Base64.getEncoder().encodeToString(publicKeyBytes);
        return EncodedPublicKey;
    }

    /**
     * Send and receive messages to CA
     * We want to e.g. Alice to send "generate publicKey"
     * this will generate certificate send it to the other client and
     * send the publicKey too
     * Then Bob receives the certificate and publicKey
     * uses the publicKey to verify the certificate
     * We want e.g. Bob to send "verify certificate publicKey"
     * CA will verifies certificate and return true/false to Bob
     */
    public void sendMsgToCA(){
        try {
            bufferedWriter.write(username);
            bufferedWriter.newLine();
            bufferedWriter.flush();

            Scanner scanner = new Scanner(System.in);

            String messageToSend = scanner.nextLine();
            if (messageToSend.equals("generate")){
                bufferedWriter.write(messageToSend + " " + encodedPublicKey());
            }
            if (messageToSend.equals("verify")){
                bufferedWriter.write(messageToSend + " " + certificate);
            }
//                bufferedWriter.write(username + ": " + messageToSend);
            bufferedWriter.newLine();
            bufferedWriter.flush();

        } catch (IOException e) {
            closeEverything(socket, bufferedReader, bufferedWriter);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void listenForMsgFromCA(){
        new Thread(new Runnable() {
            @Override
            public void run() {
                String msgFromChat;

                try {
                    GenerateCertificate generateCertificate = new GenerateCertificate();
                    msgFromChat = bufferedReader.readLine();
                    int spaceIndex = msgFromChat.indexOf(' ');
                    if (msgFromChat.substring(0,spaceIndex).equals("Certificate:")){
                        certificate = msgFromChat.substring(spaceIndex+1);
                        X509Certificate cert = generateCertificate.decodeCertificate(msgFromChat.substring(spaceIndex+1));
                        System.out.println(cert);
                    }
                    else if (msgFromChat.substring(0,spaceIndex).equals("Verified:")){
                        System.out.println(msgFromChat);
                    }
                    else {
                        System.out.println(msgFromChat);
                    }

                } catch (IOException e){
                    closeEverything(socket, bufferedReader, bufferedWriter);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        }).start();
    }

    public void closeEverything(Socket socket, BufferedReader bufferedReader, BufferedWriter bufferedWriter) {
        try {
            if (bufferedReader != null) {
                bufferedReader.close();
            }
            if (bufferedWriter != null) {
                bufferedWriter.close();
            }
            if (socket != null) {
                socket.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws IOException {

        Scanner scan = new Scanner(System.in);
        // first ask for the authentication message
        System.out.println("Enter username: ");
        String username = scan.nextLine();
        System.out.println("Generate a certificate or verify it. Select/Type (generate) or (verify): ");
        Socket CAsocket = new Socket("localhost", 12345);
        Client CAclient = new Client(CAsocket, username);
        CAclient.listenForMsgFromCA();
        CAclient.sendMsgToCA();

//        Connect to the main server and start sharing messages
//        System.out.println("Enter username: ");
//        // send key/certificate
//        Socket socket = new Socket("localhost", 1234);
//        Client client = new Client(socket, username);
//        client.listenForMessage();
//        client.sendMessage();
    }

}


