import java.nio.charset.StandardCharsets;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;


@SuppressWarnings("serial")
public class PasswordManager extends UnicastRemoteObject implements PassManagerInterface {

	private int clientId=0;
	private ArrayList<String> registeredUsers = new ArrayList<String>();
	private HashMap<String,HashMap<String,Combination>> tripletMap = new  HashMap<String,HashMap<String,Combination>>(); // String will be a Key

	public PasswordManager () throws RemoteException{}

	public String startCommunication() throws RemoteException{

		System.out.println("Connected to client with id : " + clientId);
		clientId++;
		return "Connected with server!";
	}

	public String registerUser(String key) throws RemoteException {
		// Add Key to Keystore to Register User
		if (getRegisteredUsers().contains(key)){
			System.out.println("Error registering user. ");
			return "Error: Could not register user.";
		}
		else{
			getRegisteredUsers().add(key);
			System.out.println("User with key " +key+" registered ");
			return "User successfully registered!";
		}

	}

	public String savePassword(String key, byte[] domain, byte[] username, byte[] password) throws RemoteException {
		if (getRegisteredUsers().contains(key) && key!= null){

			HashMap<String, Combination> domainsMap = new HashMap<String,Combination>();
			Combination userPassPair = new Combination (username,password);
			String domainStr = new String(domain, StandardCharsets.UTF_8);

			domainsMap.put(domainStr,userPassPair);
			tripletMap.put(key,domainsMap);

			return "Combination successfully saved on server!";
		}
		else{
			return "Error: Illegal Arguments."; // Maybe put custom Exception here
		}

	}

	public byte[] retrievePassword(String  key,byte[] domain, byte[] username) throws RemoteException {
		if (getRegisteredUsers().contains(key) && key!= null){
			String domainStr = new String(domain, StandardCharsets.UTF_8);
;
			HashMap<String, Combination> userMap = tripletMap.get(key);
			Combination userPassPair = userMap.get(domainStr);

			if (Arrays.equals(userPassPair.getUsername(),username)){
				return userPassPair.getPassword();				
			}			
		}
		return null;
	}
	public void close() throws RemoteException {
		// TODO Auto-generated method stub

	}

	public ArrayList<String> getRegisteredUsers() {
		return registeredUsers;
	}



}
