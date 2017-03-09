package pt.ulisboa.ist.sec;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Scanner;

public class KeyStore
{
    public static void main( String[] args ){

      try{
          Scanner in = new Scanner(System.in);
          System.out.println( "----- Welcome to the Keystore! -----" );
          System.out.println("Please write the number of keypairs wanted : ");
          int maxNumCertificates = in.nextInt()+1;
          for (int id=1; id<(maxNumCertificates) ; id++){
              KeyPair pair =  CertificateGenerator.generateKeyPair();
              X509Certificate[] cert = CertificateGenerator.generateCertificate(pair);
              CertificateGenerator.saveToFile(cert,id,maxNumCertificates);

          }
          System.out.println("---- All the certificates were created ! ----");
        } catch (Exception e){
          e.printStackTrace();
        }
    }
}
