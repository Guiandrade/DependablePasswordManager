package pt.ulisboa.ist.sec;


import java.nio.charset.StandardCharsets;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import javax.xml.bind.DatatypeConverter;
import java.security.*;
import javax.crypto.*;

public class PasswordManager extends UnicastRemoteObject implements PassManagerInterface {

	private int clientId=1;
	private HashMap<String,Combination> registeredUsers = new HashMap<String,Combination>();
	private HashMap<String,HashMap<Combination,String> > tripletMap = new  HashMap<String,HashMap<Combination,String> >();  // String will be a Key

	public PasswordManager () throws RemoteException {
	}

	public String startCommunication() throws RemoteException {
		System.out.println("Connected to client with id : " + clientId);
		clientId++;
		return "Connected with server!";
	}

	public String registerUser(String key) throws RemoteException, NoSuchAlgorithmException  {
		// Add Key to Keystore to Register User
		if (getRegisteredUsers().containsKey(key)) {
			System.out.println("Error registering user. ");
			return "Error: Could not register user.";
		}
		else{
			String secretKey = generateSecretKey();
			String nounce = String.valueOf(0);
			Combination combination = new Combination(secretKey,nounce);
			getRegisteredUsers().put(key,combination);
			System.out.println("User with key " +key+" registered ");
			return "User successfully registered!";
		}

	}

	public String savePassword(String key, String domain, String username, String password) throws RemoteException {
		if (getRegisteredUsers().containsKey(key) && key!= null) {
			HashMap<Combination, String> domainsMap;
			if (tripletMap.get(key)!= null){
				domainsMap = tripletMap.get(key);
			}
			else{
				domainsMap = new HashMap<Combination,String>();
			}
			Combination combination = new Combination (domain,username);
			domainsMap.put(combination,password);
			tripletMap.put(key,domainsMap);

			return "Combination successfully saved on server!";
		}
		else{
			return "Error: Illegal Arguments."; // Maybe put custom Exception here
		}

	}

	public String retrievePassword(String key,String domain, String username) throws RemoteException {
		if (getRegisteredUsers().containsKey(key) && key!= null) {
			Combination combination = new Combination (domain,username);
			HashMap<Combination,String> userMap = tripletMap.get(key);
			String result = checkCombination(combination,userMap);
			if ( result != null) {
				return result;
			}
		}
		return null; // Exception or Error?
	}
	public void close() throws RemoteException {
		// TODO Auto-generated method stub

	}

	public HashMap<String,Combination> getRegisteredUsers() {
		return registeredUsers;
	}

	public String checkCombination(Combination c,HashMap<Combination,String> userMap){
		for(Combination combinationSaved : userMap.keySet()){
			if (c.equalsTo(combinationSaved)){
				return userMap.get(combinationSaved);
			}
		}
		return null;
	}

	public String generateSecretKey() throws NoSuchAlgorithmException{
		// generate MAC secret key
		SecureRandom nonce_scr = new SecureRandom();
    KeyGenerator keyGen = KeyGenerator.getInstance("HmacMD5");
    keyGen.init(nonce_scr);
    SecretKey sk = keyGen.generateKey();

		return DatatypeConverter.printBase64Binary(sk.getEncoded());
	}




}
