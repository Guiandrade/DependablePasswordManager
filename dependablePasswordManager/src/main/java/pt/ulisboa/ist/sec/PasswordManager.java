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
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.util.concurrent.ConcurrentMap;


public class PasswordManager extends UnicastRemoteObject implements PassManagerInterface {

	private int clientId=1;
	private int certificateNum=0;
	private ConcurrentHashMap<String,ConcurrentHashMap<SecretKey,String>> registeredUsers = new ConcurrentHashMap<String,ConcurrentHashMap<SecretKey,String>>();
	private ConcurrentHashMap<String,ConcurrentHashMap<Combination,String>> tripletMap = new ConcurrentHashMap<String,ConcurrentHashMap<Combination,String> >();  // String will be a Key
	private static String publicKeyPath = "../keyStore/security/publicKeys/publickey";
	private PublicKey pubKey;
	private final Logger logger = Logger.getLogger("MyLog");
	private FileHandler fh = null;
	private static char[] ksPass = "sec".toCharArray();
	private static String keyStorePath = "../keyStore/security/keyStore/keystore.jce";
	private SecretKey secKey;

	public PasswordManager (int registryPort) throws RemoteException,IOException, NoSuchAlgorithmException,InvalidKeySpecException {
		setPublicKey();
		createLog(registryPort);
	}

	public void createLog(int registryPort) throws SecurityException,IOException {

		try {
				String logFile = "./log/LogFile-Server@"+registryPort+".log";
        // This block configure the logger with handler and formatter
        fh = new FileHandler(logFile,true);  // true allows appending to existing file
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
		clientId++;
		return "Connected with server!";
	}

	public String registerUser(String key,String signature) throws SignatureException,NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException, UnrecoverableKeyException, KeyStoreException, CertificateException  {
		// Registers or Logs User s
		if (DigitalSignature.verifySignature(stringToByte(key),stringToByte(signature),stringToByte(key))){
			logger.info("Verified Digital Signature!\n");
			SecretKey secretKey = RSAMethods.generateSecretKey();
			secKey = secretKey;
			String seqNum = String.valueOf(0);
			if(!getRegisteredUsers().containsKey(key)){
				ConcurrentHashMap<SecretKey,String> hash = new ConcurrentHashMap<SecretKey,String>();
				hash.put(secretKey, seqNum);
				registeredUsers.put(key, hash);
				logger.info("Successful registration of user with key "+key+"\n");
			}
			else{
				ConcurrentHashMap<SecretKey, String> hash = getRegisteredUsers().get(key);
				hash.put(secretKey,seqNum);
				getRegisteredUsers().put(key, hash);
				logger.info("Successful login of user with key "+key+"\n");
				seqNum = "login";
			}
			byte[] cipheredSeqNum = RSAMethods.cipher(seqNum,RSAMethods.getClientPublicKey(key));
			byte[] cipheredSecretKey = RSAMethods.cipher(byteToString(secretKey.getEncoded()),RSAMethods.getClientPublicKey(key));
			String publicKey = byteToString(pubKey.getEncoded());
			String message = publicKey + "-" + byteToString(cipheredSeqNum) + "-" + byteToString(cipheredSecretKey) + "-" + signature;
			String mac = RSAMethods.generateMAC(secretKey, message);

			return message + "-" + mac;
		}
		else{
			logger.info("Error: Could not validate signature from user with key "+key+"\n");
			return "Error-Error-Error-Error-Error";
		}
	}

	public String savePassword(String message) throws InvalidKeyException, NoSuchAlgorithmException, NumberFormatException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, IOException, SignatureException {

		String[] parts = message.split("-");
		String msg=parts[0] + "-" + parts[1] + "-" + parts[2] + "-" + parts[3] + "-" + parts[4] + "-" + parts[5] + "-" + parts[6];
		String key = parts[0];
		String seqNum = parts[1];
		String sKString = parts[2];
		String domain = parts[3];
		String username = parts[4];
		String pass = parts[5];
		String timestamp = parts[6];
		String signature = parts[7];
		String clientNonce = "";
		String requestNonce = "";
		String responseMsg = "";
		SecretKey secretKey = null;

		try {
			if(DigitalSignature.verifySignature(stringToByte(key), stringToByte(signature), stringToByte(msg))){

				logger.info("Verified Digital Signature!\n");
				byte[] secretKeyByte = RSAMethods.decipher(sKString, getPrivateKey());
				String secretKeyStr = new String(secretKeyByte, "UTF-8");
				secretKey = new SecretKeySpec(stringToByte(secretKeyStr), 0, stringToByte(secretKeyStr).length, "HmacMD5");
				clientNonce = getRegisteredUsers().get(key).get(secretKey);
				requestNonce = String.valueOf(Integer.parseInt(clientNonce)+1);
				byte[] timestampByte = RSAMethods.decipher(timestamp, getPrivateKey());
				String timestampFinal = new String(timestampByte, "UTF-8");
				System.out.println(timestampFinal);

				if(Integer.parseInt(seqNum) == Integer.parseInt(requestNonce)) {

					logger.info("Nonce confirmed!\n");
					savePasswordMap(key,domain,username,pass,timestampFinal,secretKey);
					ConcurrentHashMap<SecretKey, String> hash = getRegisteredUsers().get(key);
					hash.put(secretKey,requestNonce);
					getRegisteredUsers().put(key, hash);
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
			String msgToSend = responseMsg + "-" + signature;
			String mac = RSAMethods.generateMAC(secretKey, msgToSend);
			return msgToSend + "-" + mac;
		} catch (Exception e) {
			e.printStackTrace();
			logger.info("Error: Digital Signature not verified from savePassword request of user with key undefined \n");
			return "Error-Error-Error-Error";
		}
	}

	public String savePasswordMap(String key, String domain, String username, String password, String timestamp, SecretKey secretKey) throws RemoteException {
		if (getRegisteredUsers().containsKey(key) && key!= null) {
			ConcurrentHashMap<Combination, String> domainsMap;
			Combination combination = new Combination (domain,username,timestamp);
			if (tripletMap.get(key)!= null){
				domainsMap = tripletMap.get(key);
				String updated = updatePassword(combination, domainsMap, password, key, secretKey);
				System.out.println(updated);
				if (updated.equals("Done")){
					logger.info("Combination domain: "+domain+" ; username: "+username+" ; password: "+password+" successfully updated on server!\n");
					return "Combination successfully saved on server!";
				}
				else if (updated.equals("Add")){
					domainsMap.put(combination,password);
					tripletMap.put(key,domainsMap);
					logger.info("Combination domain: "+domain+" ; username: "+username+" ; password: "+password+" successfully updated on server!\n");
					return "Combination successfully saved on server!";
				}
			}
			else{
				domainsMap = new ConcurrentHashMap<Combination,String>();
				domainsMap.put(combination,password);
				tripletMap.put(key,domainsMap);
			}

			logger.info("Combination domain: "+domain+" ; username: "+username+" ; password: "+password+" successfully saved on server!\n");
			return "Combination successfully saved on server!";
		}
		else{
			logger.info("Error: Combination domain: "+domain+" ; username: "+username+" ; password: "+password+" can't be saved on server due to illegal arguments!\n");
			return "Error: Illegal Arguments.";
		}

	}

	public String retrievePassword(String message) throws InvalidKeyException, NumberFormatException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, IOException, SignatureException {

		String[] parts = message.split("-");
		String msg=parts[0] + "-" + parts[1] + "-" + parts[2] + "-" + parts[3] + "-" + parts[4];
		String key = parts[0];
		String nonce = parts[1];
		String secKey = parts[2];
		String domain = parts[3];
		String username = parts[4];
		String signature = parts[5];
		String clientNonce = "";
		String requestNonce = "";
		String responseMsg = "";
		SecretKey secretKey = null;

		try {
			if(DigitalSignature.verifySignature(stringToByte(key), stringToByte(signature), stringToByte(msg))){
				logger.info("Verified Digital Signature!\n");
				byte[] secretKeyByte = RSAMethods.decipher(secKey, getPrivateKey());
				String secretKeyStr = new String(secretKeyByte, "UTF-8");
				secretKey = new SecretKeySpec(stringToByte(secretKeyStr), 0, stringToByte(secretKeyStr).length, "HmacMD5");
				ConcurrentHashMap<SecretKey,String> map = registeredUsers.get(key);
				clientNonce = map.get(secretKey);
				requestNonce = String.valueOf(Integer.parseInt(clientNonce)+1);

				if(Integer.parseInt(nonce) == Integer.parseInt(requestNonce)) {
					logger.info("Nonce confirmed!\n");

					if (getRegisteredUsers().containsKey(key) && key!= null) {
						ConcurrentHashMap<SecretKey, String> hash = getRegisteredUsers().get(key);
						hash.put(secretKey,requestNonce);
						getRegisteredUsers().put(key, hash);
						Combination combination = new Combination (domain,username);
						ConcurrentHashMap<Combination,String> userMap = tripletMap.get(key);
						String result = checkCombination(combination,userMap);
						if ( result != null) {
							responseMsg = result + "-" + requestNonce;
							logger.info("Request of password for user with key "+key+" and domain "+domain+" and username "+ username+" was successful.\n");
						}
						else {
							logger.info("Error: request of user with key "+key+" and domain "+domain+" and username "+ username+", entry does not exist.\n");
							byte[] response = RSAMethods.cipher("Entry does not exist!",RSAMethods.getClientPublicKey(key));
							responseMsg = byteToString(response) + "-"+requestNonce;
						}
					}
					else {
						logger.info("Error: request of user with key "+key+", key does not exist.\n");
						byte[] response = RSAMethods.cipher("Error",RSAMethods.getClientPublicKey(key));
						responseMsg = byteToString(response) + "-"+clientNonce;
					}
				}

				else {
					logger.info("Error: Nonce incorrect.\n");
					byte[] response = RSAMethods.cipher("Error",RSAMethods.getClientPublicKey(key));
					responseMsg = byteToString(response) + "-"+clientNonce;
				}

			}
			else {
				logger.info("Error: Digital Signature not verified.\n");

				byte[] response = RSAMethods.cipher("Error",RSAMethods.getClientPublicKey(key));
				responseMsg = byteToString(response) + "-"+clientNonce;

			}
			String actualTimestamp = getTimestamp(key,domain,username);
			byte[] timestampByte = RSAMethods.cipher(actualTimestamp,RSAMethods.getClientPublicKey(key));
			String timestampStr = byteToString(timestampByte);
			String msgToSend = responseMsg + "-" + timestampStr + "-" + signature;
			String mac = RSAMethods.generateMAC(secretKey, msgToSend);

			return msgToSend + "-" + mac;
		} catch (Exception e) {
			e.printStackTrace();
			logger.info("Error: Digital Signature not verified.\n");
			return "Error-Error-Error-Error";
		}
	}

	public void close() throws RemoteException {
		for(Handler h:logger.getHandlers())
		{
    		h.close();   //must call h.close or a .LCK file will remain.
		}
			logger.info("Server successfully closed.\n");
	}

	public synchronized ConcurrentHashMap<String,ConcurrentHashMap<SecretKey,String>> getRegisteredUsers() {
		return registeredUsers;
	}

	public String checkCombination(Combination c,ConcurrentHashMap<Combination,String> userMap){
		if (userMap == null){
			return null;
		}
		for(Combination combinationSaved : userMap.keySet()){
			if (c.equalsTo(combinationSaved)){
				return userMap.get(combinationSaved);
			}
		}
		return null;
	}

	public String updatePassword(Combination c,ConcurrentHashMap<Combination,String> userMap,String pass, String key, SecretKey secretKey){
		for(Combination combinationSaved : userMap.keySet()){
			if (c.equalsTo(combinationSaved)){
				if(c.getTimeStamp() == combinationSaved.getTimeStamp()){
					for(Map.Entry<SecretKey, String> entry : registeredUsers.get(key).entrySet()){
						if(entry.getKey().equals(secretKey)){
							userMap.remove(combinationSaved);
							userMap.put(c,pass);
							return "Done";
						}
					}
				}
				else if (c.getTimeStamp() >= combinationSaved.getTimeStamp()){
					userMap.remove(combinationSaved);
					userMap.put(c,pass);
					return "Done";
				}
				else{
					return "Ignore";
				}
			}
		}
		return "Add";
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

	public String getTimestamp(String key,String domain, String username){

		if (getRegisteredUsers().containsKey(key) && key!= null) {
			ConcurrentHashMap<Combination, String> domainsMap;
			Combination c = new Combination (domain,username);

			if (tripletMap.get(key)!= null){
				domainsMap = tripletMap.get(key);
				for(Combination combinationSaved : domainsMap.keySet()){
					if (c.equalsTo(combinationSaved)){
						return Integer.toString(combinationSaved.getTimeStamp());
					}
				}
			}
			return "0";
		}
		return "Error";
	}

}
