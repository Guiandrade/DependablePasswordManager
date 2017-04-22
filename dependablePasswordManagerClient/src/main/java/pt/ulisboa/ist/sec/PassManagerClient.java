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

public class PassManagerClient{

	private PassManagerInterface passManagerInt;
	private PublicKey pubKey;
	private PublicKey serverKey;
	private SecretKey secretKey;
	private int seqNum;
	private int id;
	private ArrayList<String> serversList = new ArrayList<String>();
	private static String publicKeyPath = "../keyStore/security/publicKeys/publickey";
	//private static String privateKeyPath = "../keyStore/security/privateKeys/privatekey";
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
				serversList.add(serverURL);
			}
		}
		catch(Exception e) {System.out.println("Lookup: " + e.getMessage());}
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

	public String checkRetrievedPassword(String response, String message) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, IOException, NumberFormatException, SignatureException,KeyStoreException, UnrecoverableKeyException, CertificateException {
		String[] parts = response.split("-");
		String[] msg = message.split("-");
		String msgSent = msg[0] + "-" + msg[1] + "-" + msg[2] + "-" + msg[3] + msg[4];
		String responseMessage = parts[0];
		String responseSeqNum = parts[1];
		String responseSignature = parts[2];
		String mac = parts[3];
		String msgRecieved = responseMessage + "-" + responseSeqNum + "-" + responseSignature;
		if(RSAMethods.verifyMAC(secretKey, mac, msgRecieved)) {
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

	public String checkSavedPassword(String response,String message) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, IOException, NumberFormatException, SignatureException,KeyStoreException, UnrecoverableKeyException, CertificateException {
		String[] parts = response.split("-");
		String[] msg = message.split("-");
		String msgSent = msg[0] + "-" + msg[1] + "-" + msg[2] + "-" + msg[3] + "-" + msg[4] + "-" + msg[5];
		String responseMessage = parts[0];
		String responseSeqNum = parts[1];
		String responseSignature = parts[2];
		String mac = parts[3];
		
		String msgRecieved = responseMessage + "-" + responseSeqNum + "-" + responseSignature;
		if(RSAMethods.verifyMAC(secretKey, mac, msgRecieved)) {
			byte[] responseByte = RSAMethods.decipher(responseMessage, getPrivateKey());
			String responseString = new String(responseByte,"UTF-8");
			if(DigitalSignature.verifySignature(getPublicKey().getEncoded(), stringToByte(responseSignature), stringToByte(msgSent))) {
				if(responseString.equals("Error") || responseString.equals("Password Saved")) {
					if(seqNum+1 == Integer.parseInt(responseSeqNum)) {
						seqNum = seqNum + 1;
						return responseString;
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
		else {
			return "Error";
		}
		
	}

	public String messageToSend(String domain, String username, String pass) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, SignatureException, IOException, KeyStoreException, UnrecoverableKeyException, CertificateException {
		String publicKey = byteToString(getPublicKey().getEncoded());

		byte[] c_domain = RSAMethods.cipherPubKeyCliNoPadding(domain, getPublicKey());
		byte[] c_username = RSAMethods.cipherPubKeyCliNoPadding(username, getPublicKey());

		String send_domain = byteToString(c_domain);
		String send_username = byteToString(c_username);
		String message = "";

		if(!(pass.equals(""))) {
			byte[] c_password = RSAMethods.cipherPubKeyCliPadding(pass, getPublicKey());
			String send_password = byteToString(c_password);
			message = publicKey + "-" + String.valueOf(seqNum+1) + "-" + byteToString(RSAMethods.cipherPubKeyCliPadding(byteToString(secretKey.getEncoded()), serverKey)) + "-" + send_domain + "-" + send_username + "-" + send_password;
		}
		else {
			message = publicKey + "-" + String.valueOf(seqNum+1) + "-" + byteToString(RSAMethods.cipherPubKeyCliPadding(byteToString(secretKey.getEncoded()), serverKey)) + "-" + send_domain + "-" + send_username;
		}

		String signature = DigitalSignature.getSignature(stringToByte(message), getPrivateKey());
		message = message + "-" + signature;
		return message;
	}

	public int getId() {
		return id;
	}

	public void setId(int id) {
		this.id = id;
	}

	public void processRegisterResponse(String response, String signature) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, IOException, NumberFormatException, SignatureException, KeyStoreException, UnrecoverableKeyException, CertificateException {
		String[] parts = response.split("-");
		String msg = parts[0] + "-" + parts[1] + "-" + parts[2] + "-" + parts[3];
		String serverPubKey = parts[0];
		String cipheredNounce = parts[1];
		String secKey = parts[2];
		String sig = parts[3];
		serverKey = getServerPublicKey(serverPubKey);
		byte[] secKeyByte = RSAMethods.decipher(secKey, getPrivateKey());
		String secretKeyStr = new String(secKeyByte, "UTF-8");
		secretKey = new SecretKeySpec(stringToByte(secretKeyStr), 0, stringToByte(secretKeyStr).length, "HmacMD5");
		String mac = RSAMethods.generateMAC(secretKey, msg);
		if(RSAMethods.verifyMAC(secretKey, mac, msg)) {
			if(sig.equals(signature)) {
				byte [] keyByte = RSAMethods.decipher(cipheredNounce,getPrivateKey());
				String seqNumStr = new String(keyByte,"UTF-8");
				seqNum = 0;
				if (seqNumStr.equals("login")){
						System.out.println("User Logged In Successfuly!");
				}
				else{
						System.out.println("User Registered Successfuly!");
				}

			}
			else {
				System.out.println("Error Registering User");
			}
		}
		else {
			System.out.println("Error Registering User");
		}
	}
}
