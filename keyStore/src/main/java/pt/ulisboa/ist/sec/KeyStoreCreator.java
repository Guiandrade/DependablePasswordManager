package pt.ulisboa.ist.sec;

import java.security.*;
import javax.crypto.*;
import java.io.*;
import java.security.cert.CertificateException;

public class KeyStoreCreator {
    
  private static String keyStorePath = "security/keyStore";

  public KeyStoreCreator() {}

  public void setup() throws IOException,FileNotFoundException,KeyStoreException,NoSuchAlgorithmException,CertificateException{

    try{
      KeyStore ks = KeyStore.getInstance("JCEKS");
      ks.load(null,"sec".toCharArray());

      java.io.FileOutputStream fos = new java.io.FileOutputStream(keyStorePath+"/keystore.jce");
      ks.store(fos,"sec".toCharArray());

      fos.close();
    }
    catch(Exception e){
      e.printStackTrace();
    }

  }


}
