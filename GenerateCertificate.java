

import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;

/**
 * This class uses the Bouncycastle to generate X.509 certificates.
 * keyPairGenerator ... RSA is used to generate the public and private key
 *
 */
public class GenerateCertificate {

    private static String certificateName = "YOUR_CERTIFICATE";
    private static final String CERTIFICATE_ALGORITHM = "RSA";
    private static final String CERTIFICATE_DN = "CN=cn, O=o, L=L, ST=il, C= c";
    private static final String CERTIFICATE_NAME = "keystore.test";
    private static final int CERTIFICATE_BITS = 1024;
    private static KeyPair keyPair;
    private static PublicKey publicKey;
    private static X509Certificate certif;

    static {
        // adds the Bouncy castle provider to java security
        Security.addProvider(new BouncyCastleProvider());
    }

    // Constructor
    public GenerateCertificate() throws Exception {
        // Generate a subject's key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(CERTIFICATE_ALGORITHM);
        keyPairGenerator.initialize(CERTIFICATE_BITS, new SecureRandom());
        keyPair = keyPairGenerator.generateKeyPair();
        publicKey = keyPair.getPublic();
    }
    /**
     * The main method
     */
//    public static void main(String[] args) throws Exception {
//        GenerateCertificate signedCertificate = new GenerateCertificate();
////        KeyPair subjectKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
//
//        // Issue a certificate for the subject
//        certif = issueCertificate(publicKey);
//        System.out.println(certif);
//
//        // Verify certificate
//        boolean point = verifyCertificate(certif);
//        System.out.println(point);
//        // encode certif
//        String base64EncodedCertificate = encodeCertificate(certif);
//
//        // decode certif
//        X509Certificate certificate2 = decodeCertificate(base64EncodedCertificate);
//
//
//        System.out.println(certificate2);
//        System.out.println(verifyCertificate(certificate2));
//
//    }

    /**
     * The method for issuing the certificates
     * It generates the X509 V3 certificates
     */
    public static X509Certificate issueCertificate(PublicKey publicKey) throws Exception{

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        // GENERATE THE X509 CERTIFICATE
        X509V3CertificateGenerator certGen =  new X509V3CertificateGenerator();
        certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        certGen.setIssuerDN(new X509Principal(CERTIFICATE_DN));
//        certGen.setSubjectDN(new X509Principal("CN=" + subject));
        certGen.setNotBefore(new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24));
        certGen.setNotAfter(new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 365*10)));
        certGen.setSubjectDN(new X509Principal(CERTIFICATE_DN));
        certGen.setPublicKey(publicKey);
        certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
        X509Certificate cert = certGen.generateX509Certificate(keyPair.getPrivate());
//        saveCert(cert,keyPair.getPrivate());

        return cert;
    }



    /**
     * The method to verify a certificate
     * Returns true if it is authentic
     */
    public static boolean verifyCertificate(X509Certificate certificate) throws Exception {
        try {
//            certificate.verify(publicKey);
            certificate.checkValidity();
            return true;
        } catch (Exception e) {
            return false;
        }
    }
//    private void saveCert(X509Certificate cert, PrivateKey key) throws Exception {
//        KeyStore keyStore = KeyStore.getInstance("JKS");
//        keyStore.load(null, null);
//        keyStore.setKeyEntry(certificateName, key, "YOUR_PASSWORD".toCharArray(),  new java.security.cert.Certificate[]{cert});
//        File file = new File(".", certificateName);
//        keyStore.store( new FileOutputStream(file), "YOUR_PASSWORD".toCharArray() );
//    }

    /**
     * The method to encode a certificate
     * and decode
     */
    public static String encodeCertificate(X509Certificate cert) throws CertificateEncodingException {
        byte[] buf = cert.getEncoded();
        // cert to send
        String encodedCertificate = Base64.getEncoder().encodeToString(buf);
        return encodedCertificate;
    }

    public static X509Certificate decodeCertificate(String encodedCertificate) throws CertificateException {
        byte[] decodedCert = Base64.getDecoder().decode(encodedCertificate);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(decodedCert));
        return cert;
    }


}