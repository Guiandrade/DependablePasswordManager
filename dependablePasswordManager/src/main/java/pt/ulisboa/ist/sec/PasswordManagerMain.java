package pt.ulisboa.ist.sec;

import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class PasswordManagerMain
{
	public static void main(String args[]){
		int registryPort = 8081;
        try{
            PasswordManager passManager = new PasswordManager();
            
            Registry reg = LocateRegistry.createRegistry(registryPort);
            reg.rebind("PasswordManager", passManager);
           
            System.out.println("Server ready");
        }catch(Exception e) {
            System.out.println("Server main :" + e.getMessage());
        }
    }
}
