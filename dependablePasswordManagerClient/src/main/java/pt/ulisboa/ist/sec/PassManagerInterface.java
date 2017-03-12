package pt.ulisboa.ist.sec;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.PublicKey;


public interface PassManagerInterface extends Remote{

	public String startCommunication() throws RemoteException;
	public String registerUser(String key) throws RemoteException;
	public String savePassword(String key, String domain, String username, String password) throws RemoteException;
	public String retrievePassword(String key,String domain, String username) throws RemoteException;
	public void close() throws RemoteException;
}
