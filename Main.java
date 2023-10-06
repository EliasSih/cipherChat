public class Main {
    public static void main(String[] args) {
        final String secretKey = "donotspeakAboutTHIS";
        String originalString = "Mufhulufheli";

        String Message = "Xlj+E5gFKwgEajvf+8Raog==";

        String encSite = AES_Enctyption.encrypt(originalString, secretKey);
        String deCrypt = AES_Enctyption.decrypt(Message, secretKey);

        // System.out.println("Original Message :" +    originalString);
        // System.out.println("Encrpted Message " +    encSite);
        System.out.println(deCrypt);

    }

    
}
