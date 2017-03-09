package pt.ulisboa.ist.sec;

import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.Scanner;

public class PasswordManagerMain
{
	public static void main(String args[]){
		int registryPort = 8081;
        try{
            PasswordManager passManager = new PasswordManager();
            Scanner in = new Scanner(System.in);
						int input=-1;
            Registry reg = LocateRegistry.createRegistry(registryPort);
            reg.rebind("PasswordManager", passManager);

            System.out.println("Server ready! Input the number 0 to exit .");
						while(input!=0){
								input = in.nextInt();
						}
        }catch(Exception e) {
            System.out.println("Server main :" + e.getMessage());
        }
    }
}
