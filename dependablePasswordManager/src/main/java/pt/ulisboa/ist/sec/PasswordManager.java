package pt.ulisboa.ist.sec;


import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import javax.xml.bind.DatatypeConverter;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class PasswordManager extends UnicastRemoteObject implements PassManagerInterface {

	private int clientId=1;
	private HashMap<String,Combination> registeredUsers = new HashMap<String,Combination>();
	private HashMap<String,HashMap<Combination,String>> tripletMap = new  HashMap<String,HashMap<Combination,String> >();  // String will be a Key

	public PasswordManager () throws RemoteException {
	}

	public byte[] stringToByte(String str) {
		return DatatypeConverter.parseBase64Binary(str);
	}

	public String byteToString(byte[] byt) {
		return DatatypeConverter.printBase64Binary(byt);
	}

	public byte[] convertMsgToMac(String message, SecretKey sk) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException {
		Mac authenticator = Mac.getInstance(sk.getAlgorithm());
        authenticator.init(sk);
        byte[] msg = message.getBytes("UTF-8");
        byte[] clientMsgAuthenticator = authenticator.doFinal(msg);
		return clientMsgAuthenticator;
	}

	public byte[] cipherSk(String message, PublicKey publicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
				Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] c_message = cipher.doFinal(stringToByte(message));
        return c_message;
	}

	public String startCommunication() throws RemoteException {
		System.out.println("Connected to client with id : " + clientId);
		clientId++;
		return "Connected with server!";
	}

	public String registerUser(String key) throws RemoteException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException  {
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

			byte[] pk = stringToByte(key);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(pk);
			PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

			byte[] cipheredSecKey = cipherSk(secretKey,publicKey);

			//System.out.println("User with key " +key+" registered ");
			return byteToString(cipheredSecKey);
		}

	}
	public String savePassword(String message) throws RemoteException, InvalidKeyException, NoSuchAlgorithmException, UnsupportedEncodingException {

		String[] parts = message.split("-");
		String msg=parts[0] + "-" + parts[1] + "-" + parts[2] + "-" + parts[3];
        /*for(int i = 0;i<parts.length;i++){
        	System.out.println(parts[i]);
        }*/
        System.out.println("Key: " + parts[0] + "\n");
        System.out.println("Domain: "+parts[1]);
        System.out.println("Username: "+parts[2]);
        System.out.println("Password: "+parts[3]);

				String key = parts[0];
				String domain = parts[1];
				String username = parts[2];
				String pass = parts[3];
				String mac = parts[4];

        String secNum = getRegisteredUsers().get(key).getDomain();
        byte [] keyByte = stringToByte(secNum);
        SecretKey originalKey = new SecretKeySpec(keyByte, 0, keyByte.length, "HmacMD5");
        if(mac.equals(byteToString(convertMsgToMac(msg,originalKey)))){
        	System.out.println("MAC matching");
        	savePasswordHash(key,domain,username,pass);
        	return "Password Saved";
        }
        else {
        	System.out.println("MAC not matching");
        	return "Error saving password, try again";
        }
	}

	public String savePasswordHash(String key, String domain, String username, String password) throws RemoteException {
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
