package pt.ulisboa.ist.sec;

import java.rmi.Naming;
import java.security.*;
import java.io.*;
import java.security.spec.*;
import java.util.Base64;
import javax.xml.bind.DatatypeConverter;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class PassManagerClient{

	private PassManagerInterface passManagerInt;
	private PublicKey pubKey;
	private int id;
	private static String publicKeyPath = "../keyStore/security/publicKeys/publickey";
	private static String privateKeyPath = "../keyStore/security/privateKeys/privatekey";

	public PassManagerClient(int id){
		this.id = id;
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
	
	public String getPublicKeyString() {
		return byteToString(getPublicKey().getEncoded());
	}
	
	public byte[] stringToByte(String str) {
		return DatatypeConverter.parseBase64Binary(str);
	}
	
	public String byteToString(byte[] byt) {
		return DatatypeConverter.printBase64Binary(byt);
	}
	
	public byte[] cipher(String message) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, getPublicKey());
        byte[] c_message = cipher.doFinal(message.getBytes("UTF-8"));
        return c_message;
	}
	
	public byte[] decipher(String c_message) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, IOException {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, getPrivateKey());
        byte[] message = cipher.doFinal(c_message.getBytes("UTF-8"));
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

	public String messageToSend(String domain, String username, String pass) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException {
		String publicKey = byteToString(getPublicKey().getEncoded());
        
        byte[] c_domain = cipher(domain);
        byte[] c_username = cipher(username);
        byte[] c_password = cipher(pass);

        String send_domain = byteToString(c_domain);
        String send_username = byteToString(c_username);
        String send_password = byteToString(c_password);

        String message = publicKey + "-" + send_domain + "-" + send_username + "-" + send_password;
		return message;
	}

	public int getId() {
		return id;
	}

	public void setId(int id) {
		this.id = id;
	}

}
