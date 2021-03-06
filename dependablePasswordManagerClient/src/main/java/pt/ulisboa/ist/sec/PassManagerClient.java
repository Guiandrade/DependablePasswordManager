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
	private int id;
	private ConcurrentHashMap<PassManagerInterface,Integer> serversNums = new ConcurrentHashMap<PassManagerInterface,Integer>();
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
				serversNums.put(passManagerInt,0);
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

	public String checkRetrievedPassword(String response, String message,PassManagerInterface inter, boolean test, SecretKey sk, int seqNumber) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, IOException, NumberFormatException, SignatureException,KeyStoreException, UnrecoverableKeyException, CertificateException {
		String[] parts = response.split("-");
		String[] msg = message.split("-");
		String msgSent = msg[0] + "-" + msg[1] + "-" + msg[2] + "-" + msg[3] + "-" + msg[4];
		String responseMessage = parts[0];
		String responseSeqNum = parts[1];
		String timestamp = parts[2];
		String responseSignature = parts[3];
		String mac = parts[4];
		String msgReceived = responseMessage + "-" + responseSeqNum + "-" + timestamp + "-" + responseSignature;
		SecretKey secretKey;
		int seqNum;

		if(test==true) {
			secretKey = sk;
			seqNum = seqNumber;
		}
		else {
			secretKey = serversList.get(inter);
			seqNum = serversNums.get(inter);
		}
		if(RSAMethods.verifyMAC(secretKey, mac, msgReceived)) {
			if(DigitalSignature.verifySignature(getPublicKey().getEncoded(), stringToByte(responseSignature), stringToByte(msgSent))) {
				if(seqNum+1 ==Integer.parseInt(responseSeqNum)) {
					seqNum = seqNum + 1;
					if(test==false) {
						serversNums.put(inter,seqNum);
					}
					byte[] passwordByte = RSAMethods.decipher(responseMessage, getPrivateKey());
					String passwordStr = new String(passwordByte, "UTF-8");
					byte[] timestampByte = RSAMethods.decipher(timestamp, getPrivateKey());
					String timestampStr = new String(timestampByte, "UTF-8");
					return passwordStr + " : " + timestampStr;
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

	public synchronized String checkSavedPassword(String response,String message,PassManagerInterface inter, boolean test, SecretKey sk, int seqNumber) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, IOException, NumberFormatException, SignatureException,KeyStoreException, UnrecoverableKeyException, CertificateException {
		String[] parts = response.split("-");
		String[] msg = message.split("-");
		String msgSent = msg[0] + "-" + msg[1] + "-" + msg[2] + "-" + msg[3] + "-" + msg[4] + "-" + msg[5] + "-" + msg[6];
		String responseMessage = parts[0];
		String responseSeqNum = parts[1];
		String responseSignature = parts[2];
		String mac = parts[3];
		String msgRecieved = responseMessage + "-" + responseSeqNum + "-" + responseSignature;
		SecretKey secretKey;
		int seqNum;

		if(test==true) {
			secretKey = sk;
			seqNum = seqNumber;
		}
		else {
			secretKey = serversList.get(inter);
			seqNum = serversNums.get(inter);
		}
		if(RSAMethods.verifyMAC(secretKey, mac, msgRecieved)) {
			byte[] responseByte = RSAMethods.decipher(responseMessage, getPrivateKey());
			String responseString = new String(responseByte,"UTF-8");
			if(DigitalSignature.verifySignature(getPublicKey().getEncoded(), stringToByte(responseSignature), stringToByte(msgSent))) {
				if(responseString.equals("Error") || responseString.equals("Password Saved")) {
					if(seqNum +1 == Integer.parseInt(responseSeqNum)) {
						seqNum = seqNum + 1;
						if(test==false) {
							serversNums.put(inter,seqNum);
						}
						return responseString;
					}
					else {
						return "Error: Could not validate seqNum";
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

	public synchronized String messageToSend(String domain, String username, String pass, String timestamp, PassManagerInterface inter, boolean test) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, SignatureException, IOException, KeyStoreException, UnrecoverableKeyException, CertificateException {
		String publicKey = byteToString(getPublicKey().getEncoded());

		byte[] c_domain = RSAMethods.cipherPubKeyCliNoPadding(domain, getPublicKey());
		byte[] c_username = RSAMethods.cipherPubKeyCliNoPadding(username, getPublicKey());
		byte[] c_timestamp = RSAMethods.cipherPubKeyCliPadding(timestamp, serverKey);

		String send_domain = byteToString(c_domain);
		String send_username = byteToString(c_username);
		String send_timestamp = byteToString(c_timestamp);
		String message = "";
		int seqNum;

		if(test==false){
			seqNum = serversNums.get(inter);
		}
		else{
			seqNum = 0;
		}
		


		if((!pass.equals(""))&&(!timestamp.equals(""))) {
			// For GetTimestamps or receivePassword messages
			byte[] c_password = RSAMethods.cipherPubKeyCliPadding(pass, getPublicKey());
			String send_password = byteToString(c_password);
			if (test==false){
				message = publicKey + "-" + String.valueOf(seqNum+1) + "-" + byteToString(RSAMethods.cipherPubKeyCliPadding(byteToString(serversList.get(inter).getEncoded()), serverKey)) + "-" + send_domain + "-" + send_username + "-" + send_password + "-" + send_timestamp;
			}
			else{
				message = publicKey + "-" + String.valueOf(seqNum+1) + "-SecretKey-" + send_domain + "-" + send_username + "-" + send_password + "-" + send_timestamp;
			}
		}
		else {
			if(test==false){
				message = publicKey + "-" + String.valueOf(seqNum+1) + "-" + byteToString(RSAMethods.cipherPubKeyCliPadding(byteToString(serversList.get(inter).getEncoded()), serverKey)) + "-" + send_domain + "-" + send_username;
			}
			else{
				message = publicKey + "-" + String.valueOf(seqNum+1) + "-SecretKey-" + send_domain + "-" + send_username;
		
			}
		}

		String signature = DigitalSignature.getSignature(stringToByte(message), getPrivateKey());
		message = message + "-" + signature;
		return message;
	}

	public String registerUser(String key, String signature) throws RemoteException,InterruptedException {
		final int numServers = serversNums.size();
		final ConcurrentHashMap<PassManagerInterface,String> map = new ConcurrentHashMap<PassManagerInterface,String>();
		final String publicKey = key;
		final String sig = signature;
		final int f = (numServers - 1) / 3;
		final CountDownLatch latch = new CountDownLatch(2*f+1);

		// let's send the request to all servers and wait for the response of the majority

		for (PassManagerInterface  server : serversNums.keySet()){
			final PassManagerInterface serverInt = server;
			Thread t = new Thread(new Runnable(){
				@Override
				public void run() {
					try{
						String result;
						String response = serverInt.registerUser(publicKey,sig);
						if (processRegisterResponse(response,sig,serverInt,false,null)){
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

	public synchronized boolean processRegisterResponse(String response, String signature, PassManagerInterface server, boolean test, SecretKey sk) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, IOException, NumberFormatException, SignatureException, KeyStoreException, UnrecoverableKeyException, CertificateException {
		String[] parts = response.split("-");
		String msg = parts[0] + "-" + parts[1] + "-" + parts[2] + "-" + parts[3];
		String serverPubKey = parts[0];
		String cipheredNounce = parts[1];
		String secKey = parts[2];
		String sig = parts[3];
		String mac = parts[4];
		SecretKey secretKey;
		try{
            serverKey = getServerPublicKey(serverPubKey);
        }
        catch (Exception e){
            // Register failing test case
        }
		if(test == true) {
			secretKey = sk;
		}
		else {
			byte[] secKeyByte = RSAMethods.decipher(secKey, getPrivateKey());
			String secretKeyStr = new String(secKeyByte, "UTF-8");
			secretKey = new SecretKeySpec(stringToByte(secretKeyStr), 0, stringToByte(secretKeyStr).length, "HmacMD5");
			serversList.put(server,secretKey);
		}
		//String mac = RSAMethods.generateMAC(secretKey, msg);
		if(RSAMethods.verifyMAC(secretKey, mac, msg)) {
			if(sig.equals(signature)) {
				byte [] keyByte = RSAMethods.decipher(cipheredNounce,getPrivateKey());
				String seqNumStr = new String(keyByte,"UTF-8");
				if(test==false){
					serversNums.put(server,0);
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

	public String processRequest(String domain,String username,String pass,int timestamp, String mode) throws InvalidKeyException,IllegalBlockSizeException,BadPaddingException,NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, SignatureException, IOException, KeyStoreException, UnrecoverableKeyException, CertificateException{

		final String newTimestamp = generateTimestamp(timestamp, mode);
		final int numServers = serversNums.size();
		final int f = (numServers - 1) / 3;
		final CountDownLatch latch = new CountDownLatch(2*f+1);
		final ConcurrentHashMap<PassManagerInterface,String> mapResponses = new ConcurrentHashMap<PassManagerInterface,String>();
		final ConcurrentHashMap<Integer,String> mapReadResponses = new ConcurrentHashMap<Integer, String>();
		for(PassManagerInterface server: serversNums.keySet()){
			final PassManagerInterface serverInt = server;
			final String message = messageToSend(domain, username, pass, newTimestamp, serverInt, false);
			final String typeRequest = mode;
			Thread t = new Thread(new Runnable(){
				@Override
				public void run() {
					try{
						String response;
						String finalResponse;
						if (!typeRequest.equals("retrieve")){
							response = serverInt.savePassword(message);
							finalResponse = checkSavedPassword(response,message,serverInt,false,null,0);
						}
						else{
							response = serverInt.retrievePassword(message);
							finalResponse = checkRetrievedPassword(response,message,serverInt,false,null,0);
							String[] parts = finalResponse.split(" : ");
							int timestamp = Integer.parseInt(parts[1]);
							mapReadResponses.put(timestamp,parts[0]);
						}
						mapResponses.put(serverInt,finalResponse);
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
		String finalValue="";
		if (!mode.equals("retrieve")){
				finalValue=mapResponses.values().iterator().next();
		}
		else{
			int maxTimestamp=0;
			for(Integer ts : mapReadResponses.keySet()){
				 if (ts > maxTimestamp){
					 maxTimestamp = ts;
				 }
			}
			finalValue = mapReadResponses.get(maxTimestamp)+" : "+maxTimestamp;
		}
		return finalValue;
	}

	public ConcurrentHashMap<PassManagerInterface,Integer> getServers() {
		return serversNums;
	}

	public String generateTimestamp(int timestamp, String mode){
		// criar método para as seguintes linhas
		String newTimestamp;
		if (timestamp != -1){
			if (mode.equals("save")){
				timestamp +=1;
			}
			newTimestamp = Integer.toString(timestamp);
			return newTimestamp;
		}
		else{
			return "";
		}
	}
}
