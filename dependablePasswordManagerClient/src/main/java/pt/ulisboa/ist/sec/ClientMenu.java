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

		// Read Phase
		String response = getClient().processRequest(domain,username,"",-1,"retrieve");

		// Update Replicas
		String[] passArray = response.split(" : ");
		String pass = passArray[0];
		int timestamp = Integer.parseInt(passArray[1]);
		System.out.println("The highest timestamp on servers for that file is : "+timestamp);
		
		if (!pass.equals("Entry does not exist!")){
			String response2 = getClient().processRequest(domain,username,pass,timestamp,"writeback");
		}

		System.out.println("Your password is: "+pass);
		return response;

	}

	public void savePassword() throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, IOException, NumberFormatException, SignatureException, KeyStoreException, UnrecoverableKeyException, CertificateException {
		System.out.println("Please insert a domain : ");
		String domain = input.nextLine();
		System.out.println("Please insert an username : ");
		String username =  input.nextLine();
		System.out.println("Please insert the password: ");
		String pass =  input.nextLine();

		// Read Phase
		String response = getClient().processRequest(domain,username,"",-1,"retrieve");

		// Write Phase
		String[] passArray = response.split(" : ");
		int timestamp = Integer.parseInt(passArray[1]);
		System.out.println("The highest timestamp on servers for that file is : "+timestamp);
		String response2 = getClient().processRequest(domain,username,pass,timestamp,"save");

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
