package pt.ulisboa.ist.sec;


import java.rmi.Remote;
import java.rmi.RemoteException;

public interface PassManagerInterface extends Remote{
	
	public String startCommunication() throws RemoteException;
	public String registerUser(String key) throws RemoteException;
	public String savePassword(String  key, byte[] domain, byte[] username, byte[] password) throws RemoteException;
	public byte[] retrievePassword(String  key,byte[] domain, byte[] username) throws RemoteException;
	public void close() throws RemoteException;

}
