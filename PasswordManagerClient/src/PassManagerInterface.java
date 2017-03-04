

import java.rmi.Remote;
import java.rmi.RemoteException;

public interface PassManagerInterface extends Remote{
	
	public String startCommunication(int clientId) throws RemoteException;

}
