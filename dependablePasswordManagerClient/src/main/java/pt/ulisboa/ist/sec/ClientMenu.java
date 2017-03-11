package pt.ulisboa.ist.sec;

import java.nio.charset.StandardCharsets;
import java.rmi.RemoteException;
import java.util.Scanner;
import javax.xml.bind.DatatypeConverter;

public class ClientMenu {

	private Scanner input = new Scanner(System.in);
	private PassManagerClient client;

	public ClientMenu(PassManagerClient client){
		this.setClient(client);
	}

	public void display() throws RemoteException {
		System.out.println("----- PasswordManager Client -----");
		System.out.println(
				"Select an option: \n" +
						"  1) Register User\n" +
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
		// Complete with close() -> concludes the current session of commands with the client library.
		System.out.println("Exiting...");
		System.exit(1);

	}

	public String retrievePassword() throws RemoteException {
		// simple for testing purposes
		System.out.println("Please insert a domain : ");
		String domain =  input.nextLine();

		System.out.println("Please insert an username : ");
		String username =  input.nextLine();

		PassManagerClient client = getClient();
		PassManagerInterface stub = client.getStub();
		String key = client.getKey();

		String response = stub.retrievePassword(key,domain,username);

		if (response == null){
			System.out.println("Error retrieving password .");
			return "Error retrieving password .";
		}
		System.out.println("Your password is: "+ response);
		return response;

	}

	public void savePassword() throws RemoteException {
		// simple for testing purposes
		System.out.println("Please insert a domain : ");
		String domain = input.nextLine();
		System.out.println("Please insert an username : ");
		String  username =  input.nextLine();
		System.out.println("Please insert the password: ");
		String  pass =  input.nextLine();

		String response = getClient().getStub().savePassword(getClient().getKey(),domain,username,pass);
		System.out.println(response);
	}

	public void registerUser() throws RemoteException {
		// simple for testing purposes
		if(getClient().getKey()!= null) {
			System.out.println("User already registered");
			return;
		}
		System.out.println("Please insert a key : ");
		String key = input.nextLine();
		getClient().setKey(key);
		String response = getClient().getStub().registerUser(key);
		System.out.println(response);
	}

	public PassManagerClient getClient() {
		return client;
	}

	public void setClient(PassManagerClient client) {
		this.client = client;
	}
}
