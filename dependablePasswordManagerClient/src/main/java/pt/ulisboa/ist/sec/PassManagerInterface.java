package pt.ulisboa.ist.sec;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.PublicKey;


public interface PassManagerInterface extends Remote{

	public String startCommunication() throws RemoteException;
	public String registerUser(String key) throws RemoteException;
	public String savePassword(String message) throws RemoteException;
	public String retrievePassword(String message) throws RemoteException;
	public void close() throws RemoteException;
}
