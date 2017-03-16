package pt.ulisboa.ist.sec;

import java.io.*;
import java.io.IOException;
import java.rmi.Naming;
import java.rmi.RemoteException;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class PassManagerClient{

	private PassManagerInterface passManagerInt;
	private PublicKey pubKey;
	private SecretKey secKey;
	private PublicKey serverKey;
	private int nonce;
	private int id;
	private static String publicKeyPath = "../keyStore/security/publicKeys/publickey";
	private static String privateKeyPath = "../keyStore/security/privateKeys/privatekey";

	public PassManagerClient(int id){
		this.id = id;
	}

	public PublicKey getServerPublicKey(String key) throws InvalidKeySpecException, NoSuchAlgorithmException {
		byte[] pk = stringToByte(key);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(pk);
		PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
		return publicKey;
	}

	public void setup(){
		try{
			passManagerInt = (PassManagerInterface) Naming.lookup("//localhost:8081/PasswordManager");
			String response = passManagerInt.startCommunication();
			System.out.println("Response from Server: "+response);
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

	public String mac(String message, SecretKey sk) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException {
		Mac authenticator = Mac.getInstance(sk.getAlgorithm());
		authenticator.init(sk);
		byte[] msg = message.getBytes("UTF-8");
		byte[] clientMsgAuthenticator = authenticator.doFinal(msg);
		return byteToString(clientMsgAuthenticator);
	}

	public byte[] cipherPubKCP(String message) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, getPublicKey());
		byte[] c_message = cipher.doFinal(message.getBytes("UTF-8"));
		return c_message;
	}

	public byte[] cipherPubKCNP(String message) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
		Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
		cipher.init(Cipher.ENCRYPT_MODE, getPublicKey());
		byte[] c_message = cipher.doFinal(message.getBytes("UTF-8"));
		return c_message;
	}

	public byte[] cipherSPubK(String message) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, getServerPublicKey());
		byte[] c_message = cipher.doFinal(message.getBytes("UTF-8"));
		return c_message;
	}

	public byte[] decipher(String c_message) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, IOException {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, getPrivateKey());
		byte[] message = cipher.doFinal(stringToByte(c_message));
		return message;
	}

	public byte[] decipherSk(String c_message) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, IOException {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, getPrivateKey());
		byte[] message = cipher.doFinal(stringToByte(c_message));
		return message;
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

	public PrivateKey getPrivateKey() throws IOException, NoSuchAlgorithmException,InvalidKeySpecException {
		// Read Private Key.
		File filePrivateKey = new File(privateKeyPath + id+ ".key");
		FileInputStream fis = new FileInputStream(privateKeyPath + id+ ".key");
		byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
		fis.read(encodedPrivateKey);
		fis.close();

		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
		PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

		return privateKey;
	}

	public byte[] convertMsgToMac(String message, SecretKey sk) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException {
		Mac authenticator = Mac.getInstance(sk.getAlgorithm());
		authenticator.init(sk);
		byte[] msg = message.getBytes("UTF-8");
		byte[] clientMsgAuthenticator = authenticator.doFinal(msg);
		return clientMsgAuthenticator;
	}

	public String checkRetrievedPassword(String response) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, IOException, NumberFormatException, SignatureException {
		String[] parts = response.split("-");
		String msg = parts[0] + "-" + parts[1];
		String responseMessage = parts[0];
		String responseNonce = parts[1];
		String responseSignature = parts[2];
		if(DigitalSignature.verifySignature(getServerPublicKey().getEncoded(), stringToByte(responseSignature), stringToByte(msg))) {
			if(nonce+1 == Integer.parseInt(responseNonce)) {
				nonce = nonce + 1;
				byte[] passwordByte = decipher(responseMessage);
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

	public String checkSavedPassword(String response) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, IOException, NumberFormatException, SignatureException {
		String[] parts = response.split("-");
		String msg = parts[0] + parts[1];
		String responseMessage = parts[0];
		String responseNonce = parts[1];
		String responseSignature = parts[2];
		byte[] responseByte = decipher(responseMessage);
		String responseString = new String(responseByte,"UTF-8");
		if(DigitalSignature.verifySignature(getServerPublicKey().getEncoded(), stringToByte(responseSignature), stringToByte(msg))) {
			if(responseString.equals("Error") || responseString.equals("Password Saved")) {
				if(nonce+1 == Integer.parseInt(responseNonce)) {
					nonce = nonce + 1;
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

	public String messageToSend(String domain, String username, String pass) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, SignatureException, IOException {
		String publicKey = byteToString(getPublicKey().getEncoded());

		byte[] c_domain = cipherPubKCNP(domain);
		byte[] c_username = cipherPubKCNP(username);

		String send_domain = byteToString(c_domain);
		String send_username = byteToString(c_username);
		String message = "";

		if(!(pass.equals(""))) {
			byte[] c_password = cipherPubKCP(pass);
			String send_password = byteToString(c_password);
			message = publicKey + "-" + String.valueOf(nonce+1) + "-" + send_domain + "-" + send_username + "-" + send_password;
		}
		else {
			message = publicKey + "-" + String.valueOf(nonce+1) + "-" + send_domain + "-" + send_username;
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

	public void processRegisterResponse(String response) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, IOException {
		String[] parts = response.split("-");
		String cipheredNounce = parts[0];
		String serverPubKey = parts[1];
		serverKey = getServerPublicKey(serverPubKey);
		byte [] keyByte = decipher(cipheredNounce);
		System.out.println("keyByte -> "+keyByte);
		String nonceStr = new String(keyByte,"UTF-8");
		System.out.println("nonce -> "+nonceStr);
		nonce = Integer.parseInt(nonceStr);
	}


	public SecretKey getSecretNumber() {
		return secKey;
	}
}
