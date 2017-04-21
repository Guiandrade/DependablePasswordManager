package pt.ulisboa.ist.sec;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Scanner;


public class KeyStoreMain
{
    public static void main( String[] args ){
      // Receives number of KeyPairs to create on args[0]
      try{
          System.out.println("\n---- Welcome to the KeyStore ! ----\n");
          KeyStoreCreator ksCreator = new KeyStoreCreator();
          ksCreator.setup();

          int maxNumCertificates = Integer.parseInt(args[0]) +1;
          System.out.println("---- "+args[0]+" certificates will be created ! ----\n");
          for (int id=0; id<(maxNumCertificates) ; id++){
              KeyPair pair =  CertificateGenerator.generateKeyPair(id,maxNumCertificates);
              X509Certificate[] cert = CertificateGenerator.generateCertificate(pair);
              CertificateGenerator.saveToFile(cert,id,maxNumCertificates,pair);
          }
          System.out.println("---- All the certificates were created ! ----\n");
        } catch (Exception e){
          e.printStackTrace();
        }
    }
}
