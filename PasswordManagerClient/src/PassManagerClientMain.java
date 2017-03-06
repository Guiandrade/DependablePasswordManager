import java.rmi.RemoteException;

public class PassManagerClientMain {
	
	public static void main(String[] args) throws RemoteException {
		PassManagerClient client = new PassManagerClient();
		client.setup();
		ClientMenu menu = new ClientMenu(client);
		while(true){
			menu.display();
		}            	            
	}
}
