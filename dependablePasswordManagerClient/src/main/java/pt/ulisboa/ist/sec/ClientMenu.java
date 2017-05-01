package pt.ulisboa.ist.sec;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.rmi.RemoteException;
import java.security.*;
import java.security.spec.*;
import java.util.Scanner;
import javax.crypto.*;
import javax.xml.bind.DatatypeConverter;
import java.security.cert.CertificateException;
import java.util.concurrent.ConcurrentHashMap;

public class ClientMenu {

	private Scanner input = new Scanner(System.in);
	private PassManagerClient client;

	public ClientMenu(PassManagerClient client){
		this.setClient(client);
	}

	public void display() throws InterruptedException,SignatureException,RemoteException, IOException, NoSuchAlgorithmException,InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, CertificateException, KeyStoreException,UnrecoverableKeyException  {
		System.out.println("----- PasswordManager Client -----");
		System.out.println(
				"Select an option: \n" +
						"  1) Register/Login\n" +
						"  2) Save Password\n" +
						"  3) Retrieve Password\n" +
						"  4) Exit\n " +
						"----------------------------------"
				);

		int selection = input.nextInt();
		input.nextLine();

		switch (selection) {
		case 1:
			registerUser();
			break;
		case 2:
			savePassword();
			break;
		case 3:
			retrievePassword();
			break;
		case 4:
			exit();
			break;
		default:
			System.out.println("Invalid selection.");
			break;
		}

	}

	public void exit() {
		System.out.println("Exiting...");
		System.exit(1);

	}

	public String retrievePassword() throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, IOException, SignatureException,KeyStoreException, UnrecoverableKeyException, CertificateException  {
		System.out.println("Please insert a domain : ");
		String domain =  input.nextLine();

		System.out.println("Please insert an username : ");
		String username =  input.nextLine();

		// Request
		ConcurrentHashMap<PassManagerInterface,Integer>  mapServersMessages = getClient().getActualizedServers(domain,username);
		String response = getClient().processRetrieveRequest(domain,username,mapServersMessages);

		// Update Replicas
		String[] passArray = response.split(":");
		String pass = passArray[1];
		ConcurrentHashMap<PassManagerInterface,Integer>  mapServersMessages2 = getClient().getActualizedServers(domain,username);
		final int timestamp = mapServersMessages2.values().iterator().next();
		String response2 = getClient().processSaveRequest(domain,username,pass,timestamp,mapServersMessages2);

		System.out.println(response);
		return response;

	}

	public void savePassword() throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, IOException, NumberFormatException, SignatureException, KeyStoreException, UnrecoverableKeyException, CertificateException {
		System.out.println("Please insert a domain : ");
		String domain = input.nextLine();
		System.out.println("Please insert an username : ");
		String username =  input.nextLine();
		System.out.println("Please insert the password: ");
		String pass =  input.nextLine();

		ConcurrentHashMap<PassManagerInterface,Integer>  mapServersMessages = getClient().getActualizedServers(domain,username);
		final int timestamp = mapServersMessages.values().iterator().next();
		String response = getClient().processSaveRequest(domain,username,pass,timestamp,mapServersMessages);

		// Update Replicas
		ConcurrentHashMap<PassManagerInterface,Integer>  mapServersMessages2 = getClient().getActualizedServers(domain,username);
		final int timestamp2 = mapServersMessages2.values().iterator().next();
		String response2 = getClient().processSaveRequest(domain,username,pass,timestamp2,mapServersMessages2);

		System.out.println(response2);
	}

	public void registerUser() throws InterruptedException,SignatureException,RemoteException, IOException,NoSuchAlgorithmException,InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException,KeyStoreException, CertificateException, KeyStoreException,UnrecoverableKeyException  {
		if(getClient().getPublicKey()!= null) {
			// Implementar vários logins mesmo user
			System.out.println("User already registered");
			return;
		}
		getClient().setPublicKey(); // Find key on file

		String signature = DigitalSignature.getSignature(getClient().getPublicKey().getEncoded(),getClient().getPrivateKey());
		String result = getClient().registerUser(getClient().getPublicKeyString(),signature);

		System.out.println(result);

	}

	public PassManagerClient getClient() {
		return client;
	}

	public void setClient(PassManagerClient client) {
		this.client = client;
	}
}
