package pt.ulisboa.ist.sec;

import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.Scanner;
import java.io.IOException;
import java.security.*;
import java.security.spec.*;

public class PasswordManagerMain
{
	public static void main(String args[]) throws IOException, NoSuchAlgorithmException,InvalidKeySpecException{
		int registryPort =  Integer.parseInt(args[0]);
        try{
            PasswordManager passManager = new PasswordManager(registryPort);
            Scanner in = new Scanner(System.in);
						int input=-1;
            Registry reg = LocateRegistry.createRegistry(registryPort);
            reg.rebind("PasswordManager", passManager);

            System.out.println("Server ready at port "+registryPort+"! Input the number 0 to exit .");
						while(input!=0){
								input = in.nextInt();
						}
            passManager.close();
        }catch(Exception e) {
            System.out.println("Server main :" + e.getMessage());
        }
    }
}
