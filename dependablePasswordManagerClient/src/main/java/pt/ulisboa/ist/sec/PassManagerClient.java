package pt.ulisboa.ist.sec;

import java.io.*;
import java.io.IOException;
import java.rmi.Naming;
import java.rmi.RemoteException;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import java.util.ArrayList;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.cert.CertificateException;
import javax.xml.bind.DatatypeConverter;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.HashMap;
import java.util.concurrent.ConcurrentMap;

public class PassManagerClient{

	private PassManagerInterface passManagerInt;
	private PublicKey pubKey;
	private PublicKey serverKey;
	private int seqNum;
	private int id;
	private ArrayList<PassManagerInterface> servers = new ArrayList<PassManagerInterface>();
	private ConcurrentHashMap<PassManagerInterface,SecretKey> serversList = new ConcurrentHashMap<PassManagerInterface,SecretKey>();
	private static String publicKeyPath = "../keyStore/security/publicKeys/publickey";
	private static String keyStorePath = "../keyStore/security/keyStore/keystore.jce";
	private static char[] ksPass = "sec".toCharArray();

	public PassManagerClient(int id,String pass){
		this.id = id;
		ksPass = pass.toCharArray();
	}

	public PublicKey getServerPublicKey(String key) throws InvalidKeySpecException, NoSuchAlgorithmException {
		byte[] pk = stringToByte(key);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(pk);
		PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
		return publicKey;
	}

	public void init(int numServers){
		try{
			for (int i=1;i<=numServers;i++){
				String serverURL ="//localhost:808"+String.valueOf(i)+"/PasswordManager";
				passManagerInt = (PassManagerInterface) Naming.lookup(serverURL);
				String response = passManagerInt.startCommunication();
				System.out.println("Response from Server: "+response);
				servers.add(passManagerInt);
			}
		}
		catch(Exception e) {
			e.printStackTrace();
		}
	}

	public PassManagerInterface getStub() {
		return passManagerInt;
	}

	public PublicKey getPublicKey() {
		return pubKey;
	}

	public PublicKey getServerPublicKey() {
		return serverKey;
	}

	public String getPublicKeyString() {
		return byteToString(getPublicKey().getEncoded());
	}

	public byte[] stringToByte(String str) {
		return DatatypeConverter.parseBase64Binary(str);
	}

	public String byteToString(byte[] byt) {
		return DatatypeConverter.printBase64Binary(byt);
	}

	public void setPublicKey() throws IOException, NoSuchAlgorithmException,InvalidKeySpecException {
		// Read Public Key.
		File filePublicKey = new File(publicKeyPath + id +".key");
		FileInputStream fis = new FileInputStream(publicKeyPath + id +".key");
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

			privateKey = (PrivateKey) ks.getKey(String.valueOf(id), ksPass);
		}
		catch(Exception e){
			e.printStackTrace();
		}

		return privateKey;
	}

public int checkRetrievedTimestamp(String response, String message, PassManagerInterface server) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, IOException, NumberFormatException, SignatureException,KeyStoreException, UnrecoverableKeyException, CertificateException {
		String[] parts = response.split("-");
		String[] msg = message.split("-");
		String msgSent = msg[0] + "-" + msg[1] + "-" + msg[2] + "-" + msg[3] + msg[4];
		String responseMessage = parts[0];
		String responseSeqNum = parts[1];
		String responseSignature = parts[2];
		String mac = parts[3];
		String msgReceived = responseMessage + "-" + responseSeqNum + "-" + responseSignature;
		if(RSAMethods.verifyMAC(serversList.get(server), mac, msgReceived)) {
			if(DigitalSignature.verifySignature(getPublicKey().getEncoded(), stringToByte(responseSignature), stringToByte(msgSent))) {
				if(seqNum+1 ==Integer.parseInt(responseSeqNum)) {
					byte[] timestampByte = RSAMethods.decipher(responseMessage, getPrivateKey());
					int timestamp= Integer.parseInt(new String(timestampByte, "UTF-8"));
					System.out.println("TimeStamp for the pair on server is : "+ timestamp);
					return timestamp;
				}
				else {
					System.out.println("Error");
					return -1;
				}
			}
			else {
				System.out.println("Error");
				return -1;
			}
		}
		else {
			System.out.println("Error");
			return -1;
		}
	}

	public String checkRetrievedPassword(String response, String message,PassManagerInterface inter) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, IOException, NumberFormatException, SignatureException,KeyStoreException, UnrecoverableKeyException, CertificateException {
		String[] parts = response.split("-");
		String[] msg = message.split("-");
		String msgSent = msg[0] + "-" + msg[1] + "-" + msg[2] + "-" + msg[3] + msg[4];
		String responseMessage = parts[0];
		String responseSeqNum = parts[1];
		String responseSignature = parts[2];
		String mac = parts[3];
		String msgReceived = responseMessage + "-" + responseSeqNum + "-" + responseSignature;
		if(RSAMethods.verifyMAC(serversList.get(inter), mac, msgReceived)) {
			if(DigitalSignature.verifySignature(getPublicKey().getEncoded(), stringToByte(responseSignature), stringToByte(msgSent))) {
				if(seqNum+1 ==Integer.parseInt(responseSeqNum)) {
					seqNum = seqNum + 1;
					byte[] passwordByte = RSAMethods.decipher(responseMessage, getPrivateKey());
					String password = new String(passwordByte, "UTF-8");
					return "Your password is : "+password;
				}
				else {
					return "Error";
				}
			}
			else {
				return "Error";
			}
		}
		else {
			return "Error";
		}
	}

	public synchronized String checkSavedPassword(String response,String message,PassManagerInterface inter) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, IOException, NumberFormatException, SignatureException,KeyStoreException, UnrecoverableKeyException, CertificateException {
		String[] parts = response.split("-");
		String[] msg = message.split("-");
		String msgSent = msg[0] + "-" + msg[1] + "-" + msg[2] + "-" + msg[3] + "-" + msg[4] + "-" + msg[5];
		String responseMessage = parts[0];
		String responseSeqNum = parts[1];
		String responseSignature = parts[2];
		String mac = parts[3];
		String msgRecieved = responseMessage + "-" + responseSeqNum + "-" + responseSignature;
		if(RSAMethods.verifyMAC(serversList.get(inter), mac, msgRecieved)) {
			byte[] responseByte = RSAMethods.decipher(responseMessage, getPrivateKey());
			String responseString = new String(responseByte,"UTF-8");
			if(DigitalSignature.verifySignature(getPublicKey().getEncoded(), stringToByte(responseSignature), stringToByte(msgSent))) {
				if(responseString.equals("Error") || responseString.equals("Password Saved")) {
					System.out.println("Entra no equals e depois do verifySignature");
					if(seqNum +1 == Integer.parseInt(responseSeqNum)) {
						System.out.println("FEZ O GOLO");
						return responseString;
					}
					else {
						return "Error: seqNumber not right";
					}
				}
				else {
					return "Error in responseString";
				}
			}
			else {
				return "Error: Could not validate DigitalSignature";
			}
		}
		else {
			return "Error";
		}

	}

	public synchronized String messageToSend(String domain, String username, String pass, String timestamp, PassManagerInterface inter) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, SignatureException, IOException, KeyStoreException, UnrecoverableKeyException, CertificateException {
		String publicKey = byteToString(getPublicKey().getEncoded());

		byte[] c_domain = RSAMethods.cipherPubKeyCliNoPadding(domain, getPublicKey());
		byte[] c_username = RSAMethods.cipherPubKeyCliNoPadding(username, getPublicKey());
		byte[] c_timestamp = RSAMethods.cipherPubKeyCliNoPadding(timestamp, getPublicKey());

		String send_domain = byteToString(c_domain);
		String send_username = byteToString(c_username);
		String send_timestamp = byteToString(c_timestamp);
		String message = "";

		if((!pass.equals(""))&&(!timestamp.equals(""))) {
			// For GetTimestamps or receivePassword messages
			byte[] c_password = RSAMethods.cipherPubKeyCliPadding(pass, getPublicKey());
			String send_password = byteToString(c_password);
			message = publicKey + "-" + String.valueOf(seqNum+1) + "-" + byteToString(RSAMethods.cipherPubKeyCliPadding(byteToString(serversList.get(inter).getEncoded()), serverKey)) + "-" + send_domain + "-" + send_username + "-" + send_password + "-" + send_timestamp;
		}
		else {
			message = publicKey + "-" + String.valueOf(seqNum+1) + "-" + byteToString(RSAMethods.cipherPubKeyCliPadding(byteToString(serversList.get(inter).getEncoded()), serverKey)) + "-" + send_domain + "-" + send_username;
		}

		String signature = DigitalSignature.getSignature(stringToByte(message), getPrivateKey());
		message = message + "-" + signature;
		return message;
	}

	public String registerUser(String key, String signature) throws RemoteException,InterruptedException {
		final int numServers = serversList.size();
		final ConcurrentHashMap<PassManagerInterface,String> map = new ConcurrentHashMap<PassManagerInterface,String>();
		final String publicKey = key;
		final String sig = signature;
		final CountDownLatch latch = new CountDownLatch ( numServers/2 +1);
		// let's send the request to all servers and wait for the response of the majority

		for (PassManagerInterface  server : servers){
			final PassManagerInterface serverInt = server;
			Thread t = new Thread(new Runnable(){
				@Override
				public void run() {
					try{
							String result;
							String response = serverInt.registerUser(publicKey,sig);
							if (processRegisterResponse(response,sig,serverInt)){
									result = "Successfuly registered/logged in.";
							}
							else{
									result = "Digital Signature or seqNumber could not be verified.";
							}
							map.put(serverInt,result);
							return;
					}catch(RemoteException e){
							map.put(serverInt, e.toString());
					}catch (Exception e) {
						// byzantine
					}finally{
						latch.countDown();
					}
				}
			});
			t.start();
	}
	// wait for the majority of the replicas to reply
	try{
		latch.await();
	}catch(InterruptedException e){
		e.printStackTrace();
	}
	// get response from ConcurrentHashMap
	String finalValue=map.values().iterator().next();
	return finalValue;
}

	public synchronized boolean processRegisterResponse(String response, String signature, PassManagerInterface server) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, IOException, NumberFormatException, SignatureException, KeyStoreException, UnrecoverableKeyException, CertificateException {
		String[] parts = response.split("-");
		String msg = parts[0] + "-" + parts[1] + "-" + parts[2] + "-" + parts[3];
		String serverPubKey = parts[0];
		String cipheredNounce = parts[1];
		String secKey = parts[2];
		String sig = parts[3];
		serverKey = getServerPublicKey(serverPubKey);
		byte[] secKeyByte = RSAMethods.decipher(secKey, getPrivateKey());
		String secretKeyStr = new String(secKeyByte, "UTF-8");
		SecretKey secretKey = new SecretKeySpec(stringToByte(secretKeyStr), 0, stringToByte(secretKeyStr).length, "HmacMD5");
		serversList.put(server,secretKey);
		String mac = RSAMethods.generateMAC(secretKey, msg);
		if(RSAMethods.verifyMAC(secretKey, mac, msg)) {
			if(sig.equals(signature)) {
				byte [] keyByte = RSAMethods.decipher(cipheredNounce,getPrivateKey());
				String seqNumStr = new String(keyByte,"UTF-8");
				seqNum = 0;
				if (seqNumStr.equals("login")){
						//System.out.println("User Logged In Successfuly!");

				}
				else{
						//System.out.println("User Registered Successfuly!");
				}
				return true;
			}
			else {
				System.out.println("Signature Verification Error");
				return false;
			}
		}
		else {
			System.out.println("MAC Verification Error");
			return false;
		}
	}

	public ConcurrentHashMap<PassManagerInterface,Integer> getActualizedServers(String domain, String username) throws InvalidKeyException,IllegalBlockSizeException,BadPaddingException,NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, SignatureException, IOException, KeyStoreException, UnrecoverableKeyException, CertificateException{
		int numServers = serversList.size();
		final CountDownLatch latch = new CountDownLatch(numServers/2 +1);
		final ConcurrentHashMap<PassManagerInterface,Integer> map = new ConcurrentHashMap<PassManagerInterface,Integer>();

		for (PassManagerInterface  server : servers){
			final PassManagerInterface serverInt = server;
			final String message = messageToSend(domain, username, "", "", serverInt);

			Thread t = new Thread(new Runnable(){
				@Override
				public void run() {
					try{
							String responseTimeStamp = serverInt.retrieveTimestamp(message);
							int timestamp = checkRetrievedTimestamp(responseTimeStamp,message,serverInt);
							map.put(serverInt,timestamp);
							return;
					}catch(RemoteException e){
							// no need to handle
					}catch (Exception e) {
						// byzantine
					}finally{
						latch.countDown();
					}
				}
			});
			t.start();

		}
		// wait for the majority of the replicas to reply
		try{
			latch.await();
		}catch(InterruptedException e){
			e.printStackTrace();
		}
		// filter to have only servers with highest timestamp
		seqNum+=1;
		int maxTimeStamp=0;
		for (PassManagerInterface server : map.keySet()){
				int value = map.get(server);
				if (value >= maxTimeStamp){
						maxTimeStamp=value;
				}
				else{
						map.remove(server);
				}
		}
		return map;
	}

	public String processRetrieveRequest(String domain, String username,ConcurrentHashMap<PassManagerInterface,Integer> mapServersMessages) throws InvalidKeyException,IllegalBlockSizeException,BadPaddingException,NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, SignatureException, IOException, KeyStoreException, UnrecoverableKeyException, CertificateException{
		int numServers = mapServersMessages.size();
		final CountDownLatch latch = new CountDownLatch(numServers/2 +1);
		final ConcurrentHashMap<PassManagerInterface,String> map = new ConcurrentHashMap<PassManagerInterface,String>();

			for(PassManagerInterface server: mapServersMessages.keySet()){
				final PassManagerInterface serverInt = server;
				final String message = messageToSend(domain, username, "", "", serverInt);
					Thread t = new Thread(new Runnable(){
						@Override
						public void run() {
							try{
									String response = serverInt.retrievePassword(message);
									String finalResponse = checkRetrievedPassword(response,message,serverInt);
									map.put(serverInt,finalResponse);
									return;
								}catch(RemoteException e){
									// no need to handle
								}catch (Exception e) {
									// byzantine
								}finally{
									latch.countDown();
								}
						}
					});
					t.start();
				}

			// wait for the majority of the replicas to reply
			try{
				latch.await();
			}catch(InterruptedException e){
				e.printStackTrace();
			}
			seqNum+=1;
			String finalValue=map.values().iterator().next();
			return finalValue;
			}

			public String processSaveRequest(String domain,String username,String pass,int timestamp,ConcurrentHashMap<PassManagerInterface,Integer> map) throws InvalidKeyException,IllegalBlockSizeException,BadPaddingException,NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, SignatureException, IOException, KeyStoreException, UnrecoverableKeyException, CertificateException{
				final String newTimestamp = Integer.toString(timestamp+1);
				int numServers = map.size();
				final CountDownLatch latch = new CountDownLatch(numServers/2 +1);
				final ConcurrentHashMap<PassManagerInterface,String> mapResponses = new ConcurrentHashMap<PassManagerInterface,String>();

				for(PassManagerInterface server: map.keySet()){
					final PassManagerInterface serverInt = server;
					final String message = messageToSend(domain, username, pass, newTimestamp, serverInt);
					Thread t = new Thread(new Runnable(){
						@Override
						public void run() {
							try{
									String response = serverInt.savePassword(message);
									String finalResponse = checkSavedPassword(response,message,serverInt);
									mapResponses.put(serverInt,finalResponse);
									return;
								}catch(RemoteException e){
									// no need to handle
								}catch (Exception e) {
									// byzantine
								}finally{
									latch.countDown();
								}
						}
					});
					t.start();
				}
			// wait for the majority of the replicas to reply
			try{
				latch.await();
			}catch(InterruptedException e){
				e.printStackTrace();
			}
			seqNum+=1;
			String finalValue=mapResponses.values().iterator().next();
			return finalValue;
			}
}
