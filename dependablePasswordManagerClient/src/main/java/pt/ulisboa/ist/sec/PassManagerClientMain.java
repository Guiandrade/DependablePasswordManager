package pt.ulisboa.ist.sec;

import java.rmi.RemoteException;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.*;

public class PassManagerClientMain
{
	private static Scanner input = new Scanner(System.in);

	public static void main( String[] args ) throws SignatureException,RemoteException, IOException,NoSuchAlgorithmException,InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, UnrecoverableKeyException, CertificateException, KeyStoreException {
		// Receives id from args[0] and number of servers from args[1]
		int id = Integer.parseInt(args[0]);
		int numServers = Integer.parseInt(args[1]);
		String pass = getSecretKey();
		PassManagerClient client = new PassManagerClient(id,pass);
		client.init(numServers);
		ClientMenu menu = new ClientMenu(client);
		while(true){
			menu.display();
		}
	}


	public static String getSecretKey(){
		System.out.println("Please insert keystore password : ");
		String pass = input.nextLine();
		return pass;
	}
}
