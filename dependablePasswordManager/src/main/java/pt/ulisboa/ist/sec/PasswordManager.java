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
	private HashMap<String,Combination> registeredUsers = new HashMap<String,Combination>();
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

	public byte[] cipher(String message, PublicKey publicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] c_message = cipher.doFinal(message.getBytes("UTF-8"));
		return c_message;
	}

	public byte[] decipher(String c_message, PrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, IOException {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] message = cipher.doFinal(stringToByte(c_message));
		return message;
	}

	public PublicKey getClientPublicKey(String key) throws InvalidKeySpecException, NoSuchAlgorithmException {
		byte[] pk = stringToByte(key);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(pk);
		PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
		return publicKey;
	}

	public String startCommunication() throws RemoteException {
		System.out.println("Connected to client with id : " + clientId);
		clientId++;
		return "Connected with server!";
	}

	public String registerUser(String key,String signature) throws SignatureException,RemoteException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException  {
		// Add Key to Keystore to Register User
		if (getRegisteredUsers().containsKey(key)) {
			System.out.println("Error registering user. ");
			return "Error: Could not register user.";
		}
		else if (DigitalSignature.verifySignature(stringToByte(key),stringToByte(signature),stringToByte(key))){
			System.out.println("Verified Signature!");
			String secretKey = generateSecretKey();
			String nounce = String.valueOf(0);
			Combination combination = new Combination(secretKey,nounce);
			getRegisteredUsers().put(key,combination);

			byte[] cipheredSecKey = cipherSk(secretKey,getClientPublicKey(key));
			String publicKey = byteToString(pubKey.getEncoded());

			//Tiago aplica aqui a DigitalSignature antes de enviar

			return byteToString(cipheredSecKey) + "-" + publicKey;
		}
		return "Error: Could not validate signature.";
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
		String clientNonce = getRegisteredUsers().get(key).getNounce();
		String requestNonce = String.valueOf(Integer.parseInt(clientNonce)+1);

		System.out.println("\nKey: " + key);
		System.out.println("Nonce: "+nonce);
		System.out.println("Domain: "+domain);
		System.out.println("Username: "+username);
		System.out.println("Password: "+pass);


		//byte [] keyByte = stringToByte(secNum);
		//SecretKey originalKey = new SecretKeySpec(keyByte, 0, keyByte.length, "HmacMD5");

		if(DigitalSignature.verifySignature(stringToByte(key), stringToByte(signature), stringToByte(msg))){
			System.out.println("Verified Signature!");

			if(Integer.parseInt(nonce) == Integer.parseInt(requestNonce)) {
				System.out.println("Nonce confirmed");
				savePasswordHash(key,domain,username,pass);
				getRegisteredUsers().get(key).setNounce(requestNonce);
				byte[] response = cipher("Password Saved",getClientPublicKey(key));
				String responseStr = byteToString(response);
				String responseMsg = responseStr + "-" + requestNonce;
				String sig = DigitalSignature.getSignature(stringToByte(responseMsg), getPrivateKey());
				return responseMsg + "-" + sig;
			}

			else {
				System.out.println("Nonce incorrect");
				byte[] response = cipher("Error",getClientPublicKey(key));
				String responseStr = byteToString(response);
				String responseMsg = responseStr + "-" + clientNonce;
				String sig = DigitalSignature.getSignature(stringToByte(responseMsg), getPrivateKey());
				return responseMsg + "-" + sig;
			}

		}
		else {
			System.out.println("Signature not verified");
			byte[] response = cipher("Error",getClientPublicKey(key));
			String responseStr = byteToString(response);
			String responseMsg = responseStr + "-" + clientNonce;
			String sig = DigitalSignature.getSignature(stringToByte(responseMsg), getPrivateKey());
			return responseMsg + "-" + sig;
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

	public String retrievePassword(String message) throws InvalidKeyException, NumberFormatException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, IOException, SignatureException {
		//Tiago aplica o DigitalSignature antes de enviar

		String[] parts = message.split("-");
		String msg=parts[0] + "-" + parts[1] + "-" + parts[2] + "-" + parts[3];
		String key = parts[0];
		String nonce = parts[1];
		String domain = parts[2];
		String username = parts[3];
		String signature = parts[4];
		String clientNonce = getRegisteredUsers().get(key).getNounce();
		String requestNonce = String.valueOf(Integer.parseInt(clientNonce)+1);
		String secNum = getRegisteredUsers().get(key).getDomain();

		System.out.println("\nKey: " + key);
		System.out.println("Nonce: "+nonce);
		System.out.println("Domain: "+domain);
		System.out.println("Username: "+username);


		//byte [] keyByte = stringToByte(secNum);
		//SecretKey originalKey = new SecretKeySpec(keyByte, 0, keyByte.length, "HmacMD5");

		if(DigitalSignature.verifySignature(stringToByte(key), stringToByte(signature), stringToByte(msg))){
			System.out.println("Verified Signature!");

			if(Integer.parseInt(nonce) == Integer.parseInt(requestNonce)) {
				System.out.println("Nonce confirmed");

				if (getRegisteredUsers().containsKey(key) && key!= null) {
					getRegisteredUsers().get(key).setNounce(requestNonce);
					Combination combination = new Combination (domain,username);
					HashMap<Combination,String> userMap = tripletMap.get(key);
					String result = checkCombination(combination,userMap);
					if ( result != null) {
						String messageToSend = result + "-" + requestNonce;
						String sig = DigitalSignature.getSignature(stringToByte(messageToSend), getPrivateKey());
						return messageToSend + "-" + sig;
					}
					else {
						byte[] response = cipher("Entry doesnt exist!",getClientPublicKey(key));
						String messageToSend = byteToString(response) + "-"+requestNonce;
						String sig = DigitalSignature.getSignature(stringToByte(messageToSend), getPrivateKey());
						return messageToSend + "-" + sig;
					}
				}
				else {
					byte[] response = cipher("Error",getClientPublicKey(key));
					String messageToSend = byteToString(response) + "-"+clientNonce;
					String sig = DigitalSignature.getSignature(stringToByte(messageToSend), getPrivateKey());
					return messageToSend + "-" + sig;
				}
			}

			else {
				System.out.println("Nonce incorrect");
				byte[] response = cipher("Error",getClientPublicKey(key));
				String messageToSend = byteToString(response) + "-"+clientNonce;
				String sig = DigitalSignature.getSignature(stringToByte(messageToSend), getPrivateKey());
				return messageToSend + "-" + sig;
			}

		}
		else {
			System.out.println("Signature not verified");
			byte[] response = cipher("Error",getClientPublicKey(key));
			String messageToSend = byteToString(response) + "-"+clientNonce;
			String sig = DigitalSignature.getSignature(stringToByte(messageToSend), getPrivateKey());
			return messageToSend + "-" + sig;
		}
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
