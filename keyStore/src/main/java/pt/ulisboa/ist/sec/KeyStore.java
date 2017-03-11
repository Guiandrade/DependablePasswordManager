package pt.ulisboa.ist.sec;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Scanner;

public class KeyStore
{
    public static void main( String[] args ){

      try{
          int maxNumCertificates = chooseNumber();
          for (int id=1; id<(maxNumCertificates) ; id++){
              KeyPair pair =  CertificateGenerator.generateKeyPair(id,maxNumCertificates);
              X509Certificate[] cert = CertificateGenerator.generateCertificate(pair);
              CertificateGenerator.saveToFile(cert,id,maxNumCertificates);
          }
          System.out.println("---- All the certificates were created ! ----");
        } catch (Exception e){
          e.printStackTrace();
        }
    }

    private static int chooseNumber(){
      Scanner in = new Scanner(System.in);
      System.out.println( "----- Welcome to the Keystore! -----" );
      System.out.println("Please write the number of keypairs wanted : ");
      int maxNumCertificates = in.nextInt()+1;
      return maxNumCertificates;
    }
}
