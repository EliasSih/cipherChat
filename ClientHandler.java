package src;


import java.io.*;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;

public class ClientHandler implements Runnable{
    public static ArrayList<ClientHandler> clientHandlers = new ArrayList<>();
    private Socket socket;
    private BufferedReader bufferedReader;
    private BufferedWriter bufferedWriter;
    private String clientUsername;

    GenerateCertificate generateCertificate;
    public ClientHandler(Socket socket) {
        try {
            this.socket = socket;
            this.bufferedWriter = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
            this.bufferedReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            this.clientUsername = bufferedReader.readLine();
            clientHandlers.add(this);
            sendMessageToClient("SERVER: " + clientUsername + " has connected to the chat!");
//            broadcastMessage("SERVER: " + clientUsername + " has connected to the CA(Certificate Authority)!");

        }
        catch (IOException e) {
            closeEverything(socket, bufferedReader, bufferedWriter);
        }
    }


    /**
     * We want to e.g. Alice to send "generateCertificate publicKey"
     * this will generate certificate send it to the other client and
     * send the publicKey too
     * Then Bob receives the certificate and publicKey
     * uses the publicKey to verify the certificate
     * We want e.g. Bob to send "verifyCertificate certificate publicKey"
     * CA will verifies certificate and return true/false to Bob
     */


    @Override
    public void run() {
        String messageFromClient;
        while (socket.isConnected()) {
            try {
                messageFromClient = bufferedReader.readLine();
                // generate certificate
                generateCertificate = new GenerateCertificate();
                int spaceIndex = messageFromClient.indexOf(' ');
                if (messageFromClient.substring(0,spaceIndex).equals("generate")){
                    String encodedPKey = messageFromClient.substring(spaceIndex+1);
                    X509Certificate certificate = generateCertificate.issueCertificate(decodePublicKey(encodedPKey));
                    String cert = generateCertificate.encodeCertificate(certificate);
                    sendMessageToClient("Certificate: " + cert);
                }
                else if (messageFromClient.substring(0,spaceIndex).equals("verify")){
                    String encodedCertificate = messageFromClient.substring(spaceIndex+1);
                    X509Certificate verifyCert = generateCertificate.decodeCertificate(encodedCertificate);
                    boolean valid = generateCertificate.verifyCertificate(verifyCert);
                    messageFromClient = String.valueOf(valid);
                    sendMsg("Verified: " + messageFromClient);
                }
                else {
                    sendMessageToClient(messageFromClient);
                }

//                sendMessageToClient(messageFromClient);
            }
            catch (IOException e){
                closeEverything(socket, bufferedReader,bufferedWriter);
                break;
           } // catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }

    public void sendMessageToClient(String messageToSend){ //was initially broadcast
        for(ClientHandler clientHandler : clientHandlers) {
            try {
                if (!clientHandler.clientUsername.equals(clientUsername)) {
                    clientHandler.bufferedWriter.write(messageToSend);
                    clientHandler.bufferedWriter.newLine();
                    clientHandler.bufferedWriter.flush();

                }
            } catch (IOException e) {
                closeEverything(socket, bufferedReader, bufferedWriter);
            }
        }
    }

    public void sendMsg(String messageToSend){ //was initially broadcast
        for(ClientHandler clientHandler : clientHandlers) {
            try {
                if (clientHandler.clientUsername.equals(clientUsername)) {
                    clientHandler.bufferedWriter.write(messageToSend);
                    clientHandler.bufferedWriter.newLine();
                    clientHandler.bufferedWriter.flush();

                }
            } catch (IOException e) {
                closeEverything(socket, bufferedReader, bufferedWriter);
            }
        }
    }


    public void removeClientHandler() {
        clientHandlers.remove(this);
        sendMessageToClient("SERVER: " + clientUsername + " has left the chat!");
        System.out.println("SERVER: " + clientUsername + " has left the chat!");
    }

    public void closeEverything(Socket socket, BufferedReader bufferedReader, BufferedWriter bufferedWriter) {
        removeClientHandler();
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

    public PublicKey decodePublicKey(String encodedPublicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // Decode the Base64-encoded public key into a byte array
        byte[] publicKeyBytes = Base64.getDecoder().decode(encodedPublicKey);

        // Create an X509EncodedKeySpec to represent the public key
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);

        // Get a KeyFactory for the desired algorithm (e.g., RSA or EC)
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);

        return publicKey;

    }


}