package pt.ulisboa.ist.sec;


import sun.security.x509.X509CertInfo;
import java.io.*;
import java.security.*;
import java.security.spec.*;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Date;
import sun.security.x509.*;
import java.nio.charset.Charset;


public class CertificateGenerator {

    private static String certificatePath = "security/certificates/certificate";
    private static String publicKeyPath = "security/publicKeys/publickey";
    private static String privateKeyPath = "security/privateKeys/privatekey";

    public static X509Certificate[] generateCertificate(KeyPair pair) throws Exception {
        X509CertInfo info = new X509CertInfo();
        Date from = new Date();
        Date to = new Date(from.getTime() + 365 * 86400000l); //1 year
        CertificateValidity interval = new CertificateValidity(from, to);
        X500Name owner = new X500Name("C=PT, ST=SEC");

        info.set(X509CertInfo.VALIDITY, interval);
        info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(new BigInteger(64, new SecureRandom())));
        info.set(X509CertInfo.SUBJECT, owner);
        info.set(X509CertInfo.ISSUER,owner);
        info.set(X509CertInfo.KEY, new CertificateX509Key(pair.getPublic()));
        info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
        AlgorithmId algo = new AlgorithmId(AlgorithmId.md5WithRSAEncryption_oid);
        info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algo));
        X509CertImpl cert = new X509CertImpl(info);
        cert.sign(pair.getPrivate(), "SHA1withRSA");
        algo = (AlgorithmId)cert.get(X509CertImpl.SIG_ALG);
        info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, algo);
        cert = new X509CertImpl(info);
        cert.sign(pair.getPrivate(), "SHA1withRSA");
        return new X509Certificate[]{cert};
      }

  public static boolean saveToFile(X509Certificate[] cert,int id,int max){

      try{
        byte[] buf = cert[0].getEncoded();
        File file = new File(certificatePath+id+".dat");
        file.createNewFile(); // if file already exists will do nothing
        FileOutputStream os= new FileOutputStream(file, false);
        os.write(buf);
        if (id==max){
            os.close();
        }


        Writer wr = new OutputStreamWriter(os, Charset.forName("UTF-8"));
        wr.write(new sun.misc.BASE64Encoder().encode(buf));
        wr.flush();
        return true;
      }
      catch (Exception e){
        e.printStackTrace();
        return false;
      }
  }

  public static KeyPair generateKeyPair(int id, int max){
    try{
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        keyGen.initialize(2048, random);
        KeyPair pair = keyGen.generateKeyPair();

        saveKeyPair(pair,id,max);

        return pair;
      }
      catch (Exception e){
        e.printStackTrace();
        return null;
      }
  }
   public static void saveKeyPair(KeyPair keyPair, int id, int max) throws IOException {
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // Store Public Key.
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
        FileOutputStream fos = new FileOutputStream(publicKeyPath+id+".key");
        fos.write(x509EncodedKeySpec.getEncoded());

         // Store Private Key.
         PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
         FileOutputStream os = new FileOutputStream(privateKeyPath+id+".key");
         os.write(pkcs8EncodedKeySpec.getEncoded());
         if (id==max){
             fos.close();
             os.close();
         }
   }
/*
   public static KeyPair loadKeyPair(String path, String algorithm)
    // to use on client
     throws IOException, NoSuchAlgorithmException,
     InvalidKeySpecException {
     // Read Public Key.
     File filePublicKey = new File(path + "/public.key");
     FileInputStream fis = new FileInputStream(path + "/public.key");
     byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
     fis.read(encodedPublicKey);
     fis.close();

     // Read Private Key.
     File filePrivateKey = new File(path + "/private.key");
     fis = new FileInputStream(path + "/private.key");
     byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
     fis.read(encodedPrivateKey);
     fis.close();

     // Generate KeyPair.
     KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
     X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
     PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

     PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
     PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

     return new KeyPair(publicKey, privateKey);
   }*/
}
