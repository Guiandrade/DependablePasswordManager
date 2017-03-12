package pt.ulisboa.ist.sec;

import java.rmi.RemoteException;
import java.util.Scanner;
import java.io.IOException;
import java.security.*;
import java.security.spec.*;

public class PassManagerClientMain
{
	public static void main( String[] args ) throws RemoteException, IOException,NoSuchAlgorithmException,InvalidKeySpecException {
		Scanner input = new Scanner(System.in);
		System.out.println("Please insert client id: ");
		int selection = input.nextInt();
		input.nextLine();
		PassManagerClient client = new PassManagerClient(selection);
		client.setup();
		ClientMenu menu = new ClientMenu(client);
		while(true){
			menu.display();
		}
	}
}
