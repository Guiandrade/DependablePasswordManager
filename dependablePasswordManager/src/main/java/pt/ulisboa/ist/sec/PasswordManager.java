package pt.ulisboa.ist.sec;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.security.*;
import java.security.spec.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;


public class PasswordManager extends UnicastRemoteObject implements PassManagerInterface {

	private int clientId=1;
	private int certificateNum=0;
	private HashMap<String,String> registeredUsers = new HashMap<String,String>();
	private HashMap<String,HashMap<Combination,String>> tripletMap = new  HashMap<String,HashMap<Combination,String> >();  // String will be a Key
	private static String publicKeyPath = "../keyStore/security/publicKeys/publickey";
	private static String privateKeyPath = "../keyStore/security/privateKeys/privatekey";
	private PublicKey pubKey;

	public PasswordManager () throws RemoteException,IOException, NoSuchAlgorithmException,InvalidKeySpecException {
		setPublicKey();
	}

	public byte[] stringToByte(String str) {
		return DatatypeConverter.parseBase64Binary(str);
	}

	public String byteToString(byte[] byt) {
		return DatatypeConverter.printBase64Binary(byt);
	}

	public String startCommunication() throws RemoteException {
		System.out.println("Connected to client with id : " + clientId);
		clientId++;
		return "Connected with server!";
	}

	public String registerUser(String key,String signature) throws SignatureException,NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException  {
		// Registers or Logs User s
		String secretKey;
		String nounce;
		if (DigitalSignature.verifySignature(stringToByte(key),stringToByte(signature),stringToByte(key))){
			System.out.println("Verified Signature!");
			if(!getRegisteredUsers().containsKey(key)){
				secretKey = generateSecretKey();
				nounce = String.valueOf(0);
				getRegisteredUsers().put(key,nounce);
			}
			else{
				nounce = getRegisteredUsers().get(key);
			}

			byte[] cipheredNounce = RSAMethods.cipher(nounce,RSAMethods.getClientPublicKey(key));
			String publicKey = byteToString(pubKey.getEncoded());
			String message = byteToString(cipheredNounce) + "-" + publicKey;
			String sig = DigitalSignature.getSignature(stringToByte(message), getPrivateKey());

			return message + "-" + sig;
		}
		else{
			return "Error: Could not validate signature.";
		}

	}

	public String savePassword(String message) throws InvalidKeyException, NoSuchAlgorithmException, NumberFormatException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, IOException, SignatureException {

		String[] parts = message.split("-");
		String msg=parts[0] + "-" + parts[1] + "-" + parts[2] + "-" + parts[3] + "-" + parts[4];
		String key = parts[0];
		String nonce = parts[1];
		String domain = parts[2];
		String username = parts[3];
		String pass = parts[4];
		String signature = parts[5];
		String clientNonce = getRegisteredUsers().get(key);
		String requestNonce = String.valueOf(Integer.parseInt(clientNonce)+1);

		if(DigitalSignature.verifySignature(stringToByte(key), stringToByte(signature), stringToByte(msg))){
			System.out.println("Verified Signature!");

			if(Integer.parseInt(nonce) == Integer.parseInt(requestNonce)) {
				System.out.println("Nonce confirmed");
				savePasswordMap(key,domain,username,pass);
				getRegisteredUsers().put(key,requestNonce);
				byte[] response = RSAMethods.cipher("Password Saved",RSAMethods.getClientPublicKey(key));
				String responseStr = byteToString(response);
				String responseMsg = responseStr + "-" + requestNonce;
				String sig = DigitalSignature.getSignature(stringToByte(responseMsg), getPrivateKey());
				return responseMsg + "-" + sig;
			}

			else {
				System.out.println("Nonce incorrect");
				byte[] response = RSAMethods.cipher("Error",RSAMethods.getClientPublicKey(key));
				String responseStr = byteToString(response);
				String responseMsg = responseStr + "-" + clientNonce;
				String sig = DigitalSignature.getSignature(stringToByte(responseMsg), getPrivateKey());
				return responseMsg + "-" + sig;
			}

		}
		else {
			System.out.println("Signature not verified");
			byte[] response = RSAMethods.cipher("Error",RSAMethods.getClientPublicKey(key));
			String responseStr = byteToString(response);
			String responseMsg = responseStr + "-" + clientNonce;
			String sig = DigitalSignature.getSignature(stringToByte(responseMsg), getPrivateKey());
			return responseMsg + "-" + sig;
		}
	}

	public String savePasswordMap(String key, String domain, String username, String password) throws RemoteException {
		if (getRegisteredUsers().containsKey(key) && key!= null) {
			HashMap<Combination, String> domainsMap;
			Combination combination = new Combination (domain,username);
			if (tripletMap.get(key)!= null){
				domainsMap = tripletMap.get(key);
				if (updatePassword(combination, domainsMap, password)){
					return "Combination successfully saved on server!";
				}
			}
			else{
				domainsMap = new HashMap<Combination,String>();
			}

			domainsMap.put(combination,password);
			tripletMap.put(key,domainsMap);

			return "Combination successfully saved on server!";
		}
		else{
			return "Error: Illegal Arguments."; // Maybe put custom Exception here
		}

	}

	public String retrievePassword(String message) throws InvalidKeyException, NumberFormatException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, IOException, SignatureException {

		String[] parts = message.split("-");
		String msg=parts[0] + "-" + parts[1] + "-" + parts[2] + "-" + parts[3];
		String key = parts[0];
		String nonce = parts[1];
		String domain = parts[2];
		String username = parts[3];
		String signature = parts[4];
		String clientNonce = getRegisteredUsers().get(key);
		String requestNonce = String.valueOf(Integer.parseInt(clientNonce)+1);
		String messageToSend;

		if(DigitalSignature.verifySignature(stringToByte(key), stringToByte(signature), stringToByte(msg))){
			System.out.println("Verified Signature!");

			if(Integer.parseInt(nonce) == Integer.parseInt(requestNonce)) {
				System.out.println("Nonce confirmed");

				if (getRegisteredUsers().containsKey(key) && key!= null) {
					getRegisteredUsers().put(key,requestNonce);
					Combination combination = new Combination (domain,username);
					HashMap<Combination,String> userMap = tripletMap.get(key);
					String result = checkCombination(combination,userMap);
					if ( result != null) {
						messageToSend = result + "-" + requestNonce;
					}
					else {
						byte[] response = RSAMethods.cipher("Entry doesnt exist!",RSAMethods.getClientPublicKey(key));
						messageToSend = byteToString(response) + "-"+requestNonce;
					}
				}
				else {
					byte[] response = RSAMethods.cipher("Error",RSAMethods.getClientPublicKey(key));
					messageToSend = byteToString(response) + "-"+clientNonce;
				}
			}

			else {
				System.out.println("Nonce incorrect");
				byte[] response = RSAMethods.cipher("Error",RSAMethods.getClientPublicKey(key));
				messageToSend = byteToString(response) + "-"+clientNonce;
			}

		}
		else {
			System.out.println("Signature not verified");

			byte[] response = RSAMethods.cipher("Error",RSAMethods.getClientPublicKey(key));
			messageToSend = byteToString(response) + "-"+clientNonce;

		}
		String sig = DigitalSignature.getSignature(stringToByte(messageToSend), getPrivateKey());
		return messageToSend + "-" + sig;
	}

	public void close() throws RemoteException {
		// TODO Auto-generated method stub

	}

	public HashMap<String,String> getRegisteredUsers() {
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

	public boolean updatePassword(Combination c,HashMap<Combination,String> userMap,String pass){
		for(Combination combinationSaved : userMap.keySet()){
			if (c.equalsTo(combinationSaved)){
				userMap.put(combinationSaved,pass);
				return true;
			}
		}
		return false;
	}

	public String generateSecretKey() throws NoSuchAlgorithmException{
		// generate MAC secret key
		SecureRandom nonce_scr = new SecureRandom();
		KeyGenerator keyGen = KeyGenerator.getInstance("HmacMD5");
		keyGen.init(nonce_scr);
		SecretKey sk = keyGen.generateKey();

		return DatatypeConverter.printBase64Binary(sk.getEncoded());
	}

	public void setPublicKey() throws IOException, NoSuchAlgorithmException,InvalidKeySpecException {
		// Read Public Key.
		File filePublicKey = new File(publicKeyPath + certificateNum +".key");
		FileInputStream fis = new FileInputStream(publicKeyPath + certificateNum +".key");
		byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
		fis.read(encodedPublicKey);
		fis.close();

		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
		PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

		pubKey = publicKey;
	}

	public PrivateKey getPrivateKey() throws IOException, NoSuchAlgorithmException,InvalidKeySpecException {
		// Read Private Key.
		File filePrivateKey = new File(privateKeyPath + certificateNum+ ".key");
		FileInputStream fis = new FileInputStream(privateKeyPath + certificateNum+ ".key");
		byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
		fis.read(encodedPrivateKey);
		fis.close();

		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
		PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

		return privateKey;
	}
}
