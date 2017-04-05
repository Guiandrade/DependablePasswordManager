package pt.ulisboa.ist.sec;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.logging.*;
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
	private final Logger logger = Logger.getLogger("MyLog");  
    private FileHandler fh = null;
    private static char[] ksPass = "sec".toCharArray();
    private static String keyStorePath = "../keyStore/security/keyStore/keystore.jce";

	public PasswordManager () throws RemoteException,IOException, NoSuchAlgorithmException,InvalidKeySpecException {
		setPublicKey();
		createLog();
		
	}

	public void createLog() throws SecurityException,IOException {

		try {  

        // This block configure the logger with handler and formatter  
        fh = new FileHandler("./log/LogFile.log",true);  // true allows appending to existing file
        logger.addHandler(fh);
        SimpleFormatter formatter = new SimpleFormatter();  
        fh.setFormatter(formatter);  

        // the following statement is used to log any messages  
        logger.info("Server using log file!\n");  

    	} catch (SecurityException e) {  
        	e.printStackTrace();  
    	} catch (IOException e) {  
        	e.printStackTrace();  
    	}  
	}

	public byte[] stringToByte(String str) {
		return DatatypeConverter.parseBase64Binary(str);
	}

	public String byteToString(byte[] byt) {
		return DatatypeConverter.printBase64Binary(byt);
	}

	public String startCommunication() throws RemoteException {
		// TO DO KEY/Ip,port PAIR to allow multiple devices
		logger.info("Connected to client with pair key/ip,port : " + "TO DO\n");
		clientId++;
		return "Connected with server!";
	}

	public String registerUser(String key,String signature) throws SignatureException,NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException, UnrecoverableKeyException, KeyStoreException, CertificateException  {
		// Registers or Logs User s
		String secretKey;
		String seqNum;
		if (DigitalSignature.verifySignature(stringToByte(key),stringToByte(signature),stringToByte(key))){
			logger.info("Verified Digital Signature!\n");
			if(!getRegisteredUsers().containsKey(key)){
				secretKey = generateSecretKey();
				seqNum = String.valueOf(0);
				getRegisteredUsers().put(key,seqNum);
				logger.info("Successful registration of user with key "+key+"\n");
			}
			else{
				seqNum = getRegisteredUsers().get(key);
				logger.info("Successful login of user with key "+key+"\n");
			}

			byte[] cipheredSeqNum = RSAMethods.cipher(seqNum,RSAMethods.getClientPublicKey(key));
			String publicKey = byteToString(pubKey.getEncoded());
			String message = byteToString(cipheredSeqNum) + "-" + publicKey;
			String sig = DigitalSignature.getSignature(stringToByte(message), getPrivateKey());

			return message + "-" + sig;
		}
		else{
			logger.info("Error: Could not validate signature from user with key "+key+"\n"); 
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
		String requestNonce = "";
		String responseMsg = "";

		try {
			if(DigitalSignature.verifySignature(stringToByte(key), stringToByte(signature), stringToByte(msg))){
				logger.info("Verified Digital Signature!\n");
				
				requestNonce = String.valueOf(Integer.parseInt(clientNonce)+1);
				if(Integer.parseInt(nonce) == Integer.parseInt(requestNonce)) {
					logger.info("Nonce confirmed!\n");
					savePasswordMap(key,domain,username,pass);
					getRegisteredUsers().put(key,requestNonce);
					byte[] response = RSAMethods.cipher("Password Saved",RSAMethods.getClientPublicKey(key));
					String responseStr = byteToString(response);
					responseMsg = responseStr + "-" + requestNonce;
					
				}

				else {
					logger.info("Error: Nonce incorrect from savePassword request of user with key "+key+"\n");
					byte[] response = RSAMethods.cipher("Error",RSAMethods.getClientPublicKey(key));
					String responseStr = byteToString(response);
					responseMsg = responseStr + "-" + clientNonce;
				}

			}
			else {
				logger.info("Error: Digital Signature not verified from savePassword request of user with key "+key+"\n");
				byte[] response = RSAMethods.cipher("Error",RSAMethods.getClientPublicKey(key));
				String responseStr = byteToString(response);
				responseMsg = responseStr + "-" + clientNonce;
			}
			
			return responseMsg + "-" + signature;
		} catch (Exception e) {
			logger.info("Error: Digital Signature not verified from savePassword request of user with key undefined \n");
			return "Error-Error-Error";
		}
	}

	public String savePasswordMap(String key, String domain, String username, String password) throws RemoteException {
		if (getRegisteredUsers().containsKey(key) && key!= null) {
			HashMap<Combination, String> domainsMap;
			Combination combination = new Combination (domain,username);
			if (tripletMap.get(key)!= null){
				domainsMap = tripletMap.get(key);
				if (updatePassword(combination, domainsMap, password)){
					logger.info("Combination domain: "+domain+" ; username: "+username+" ; password: "+password+" successfully updated on server!\n");
					return "Combination successfully saved on server!";
				}
			}
			else{
				domainsMap = new HashMap<Combination,String>();
			}

			domainsMap.put(combination,password);
			tripletMap.put(key,domainsMap);

			logger.info("Combination domain: "+domain+" ; username: "+username+" ; password: "+password+" successfully saved on server!\n");
			return "Combination successfully saved on server!";
		}
		else{
			logger.info("Error: Combination domain: "+domain+" ; username: "+username+" ; password: "+password+" can't be saved on server due to illegal arguments!\n");
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
		String requestNonce = "";
		String messageToSend;

		try {
			if(DigitalSignature.verifySignature(stringToByte(key), stringToByte(signature), stringToByte(msg))){
				logger.info("Verified Digital Signature!\n");
				
				requestNonce = String.valueOf(Integer.parseInt(clientNonce)+1);

				if(Integer.parseInt(nonce) == Integer.parseInt(requestNonce)) {
					logger.info("Nonce confirmed!\n");

					if (getRegisteredUsers().containsKey(key) && key!= null) {
						getRegisteredUsers().put(key,requestNonce);
						Combination combination = new Combination (domain,username);
						HashMap<Combination,String> userMap = tripletMap.get(key);
						String result = checkCombination(combination,userMap);
						if ( result != null) {
							messageToSend = result + "-" + requestNonce;
							logger.info("Request of password for user with key "+key+" and domain "+domain+" and username "+ username+" was successful.\n");
						}
						else {
							logger.info("Error: request of user with key "+key+" and domain "+domain+" and username "+ username+", entry does not exist.\n");
							byte[] response = RSAMethods.cipher("Entry does not exist!",RSAMethods.getClientPublicKey(key));
							messageToSend = byteToString(response) + "-"+requestNonce;
						}
					}
					else {
						logger.info("Error: request of user with key "+key+", key does not exist.\n");
						byte[] response = RSAMethods.cipher("Error",RSAMethods.getClientPublicKey(key));
						messageToSend = byteToString(response) + "-"+clientNonce;
					}
				}

				else {
					logger.info("Error: Nonce incorrect.\n");
					byte[] response = RSAMethods.cipher("Error",RSAMethods.getClientPublicKey(key));
					messageToSend = byteToString(response) + "-"+clientNonce;
				}

			}
			else {
				logger.info("Error: Digital Signature not verified.\n");

				byte[] response = RSAMethods.cipher("Error",RSAMethods.getClientPublicKey(key));
				messageToSend = byteToString(response) + "-"+clientNonce;

			}
			
			return messageToSend + "-" + signature;
		} catch (Exception e) {
			logger.info("Error: Digital Signature not verified.\n");
			
			return "Error-Error-Error";
		}
	}

	public void close() throws RemoteException {
		for(Handler h:logger.getHandlers())
		{
    		h.close();   //must call h.close or a .LCK file will remain.
		}
			logger.info("Server successfully closed.\n");
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

	public PrivateKey getPrivateKey() throws IOException,KeyStoreException,NoSuchAlgorithmException,CertificateException, UnrecoverableKeyException {
		// Read Private Key.
		
		PrivateKey privateKey = null;
		try {
			FileInputStream fis = new FileInputStream(keyStorePath);

			KeyStore ks = KeyStore.getInstance("JCEKS");

			ks.load(fis,ksPass);
			
			fis.close();

			privateKey = (PrivateKey) ks.getKey(String.valueOf(0), ksPass);
		}
		catch(Exception e){
			e.printStackTrace();
		}

		return privateKey;
	}
}
