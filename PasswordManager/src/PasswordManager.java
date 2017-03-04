

import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;


public class PasswordManager extends UnicastRemoteObject implements PassManagerInterface {
	
	public PasswordManager () throws RemoteException{}
	
	public String startCommunication(int clientId) throws RemoteException{
		
		System.out.println("Connected to client with id : " + clientId);
		return "Connected with server!";
	}
}
