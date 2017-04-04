package pt.ulisboa.ist.sec;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Scanner;


public class KeyStoreMain
{
    public static void main( String[] args ){

      try{

          KeyStoreCreator ksCreator = new KeyStoreCreator();
          ksCreator.setup();

          int maxNumCertificates = chooseNumber();
          for (int id=0; id<(maxNumCertificates) ; id++){
              KeyPair pair =  CertificateGenerator.generateKeyPair(id,maxNumCertificates);
              X509Certificate[] cert = CertificateGenerator.generateCertificate(pair);
              CertificateGenerator.saveToFile(cert,id,maxNumCertificates,pair);
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
