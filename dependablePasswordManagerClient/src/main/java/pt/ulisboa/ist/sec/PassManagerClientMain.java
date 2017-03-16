package pt.ulisboa.ist.sec;

import java.rmi.RemoteException;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import java.io.IOException;
import java.security.*;
import java.security.spec.*;

public class PassManagerClientMain
{
	public static void main( String[] args ) throws SignatureException,RemoteException, IOException,NoSuchAlgorithmException,InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException {
		Scanner input = new Scanner(System.in);
		System.out.println("Please insert client id: ");
		int selection = input.nextInt();
		input.nextLine();
		PassManagerClient client = new PassManagerClient(selection);
		client.init();
		ClientMenu menu = new ClientMenu(client);
		while(true){
			menu.display();
		}
	}
}
