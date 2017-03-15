package pt.ulisboa.ist.sec;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;


public interface PassManagerInterface extends Remote{

	public String startCommunication() throws RemoteException;
	public String registerUser(String key) throws RemoteException,NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException;;
	public String savePassword(String message) throws RemoteException, InvalidKeyException, NoSuchAlgorithmException, UnsupportedEncodingException, NumberFormatException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, IOException;
	public String retrievePassword(String message) throws InvalidKeyException, NumberFormatException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, IOException;
	public void close() throws RemoteException;
}
