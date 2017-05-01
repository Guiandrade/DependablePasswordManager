package pt.ulisboa.ist.sec;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.rmi.RemoteException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

public class ServerTest {
	
	private static PublicKey cliPubKey;
	private static PrivateKey cliPrivKey;
	private static PublicKey servPubKey;
	private static PrivateKey servPrivKey;
	private static SecretKey secretKey;
	private static String publicKeyPath = "../keyStore/security/publicKeys/publickey";
	private static String keyStorePath = "../keyStore/security/keyStore/keystore.jce";
	private static char[] ksPass = "sec".toCharArray();
	
	@BeforeClass
	public static void keyInitializations() throws NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException, CertificateException, IOException, InvalidKeySpecException {
		
        KeyPairGenerator keyGenServ = KeyPairGenerator.getInstance("RSA");
        SecureRandom randomServ = SecureRandom.getInstance("SHA1PRNG");
        keyGenServ.initialize(2048, randomServ);
        KeyPair pairServ = keyGenServ.generateKeyPair();
        servPrivKey = pairServ.getPrivate();
        cliPrivKey = getPrivateKey();
        setPublicKey();
	}

	///////////////////////// SECURITY TESTS /////////////////////////
	
	// REGISTER USER TESTS
	
	@Test
	public void registerUserTest() throws RemoteException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException, KeyStoreException, CertificateException {
		
		// Creation of the server
		PasswordManager pm = new PasswordManager(8080);

		// Normal register
		String response = pm.registerUser(DatatypeConverter.printBase64Binary(cliPubKey.getEncoded()), 
				DigitalSignature.getSignature(cliPubKey.getEncoded(),cliPrivKey));

		// Analyse the correctness of the answer
		Assert.assertNotSame(response, "Error: Could not validate signature.");
	}
	
	@Test
	public void registerUserFailingTest() throws RemoteException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException, KeyStoreException, CertificateException {
		
		// Creation of the server
		PasswordManager pm = new PasswordManager(8080);

		// Register with a malformed message
		String response = pm.registerUser(DatatypeConverter.printBase64Binary(cliPubKey.getEncoded()), 
				DigitalSignature.getSignature(cliPubKey.getEncoded(),servPrivKey));
		
		// Analyse the correctness of the answer
		Assert.assertEquals(response, "Error-Error-Error-Error-Error");
	}
	
	// SAVE PASSWORD TESTS
	
	@Test
	public void savePasswordTest() throws RemoteException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException, KeyStoreException, CertificateException {
		
		// Creation of the server and registration
		PasswordManager pm = new PasswordManager(8080);
		String responseRegister = pm.registerUser(byteToString(cliPubKey.getEncoded()), 
				DigitalSignature.getSignature(cliPubKey.getEncoded(),cliPrivKey));
		
		// Set global variables for Secret Key and Server Public Key that based on the register
		byte[] secretKeyByte = RSAMethods.decipher(responseRegister.split("-")[2], cliPrivKey);
		String secretKeyStr = new String(secretKeyByte, "UTF-8");
		secretKey = new SecretKeySpec(stringToByte(secretKeyStr), 0, stringToByte(secretKeyStr).length, "HmacMD5");
		servPubKey = getServerPublicKey(responseRegister.split("-")[0]);
		
		// Simulate the request from client
		String domain = "facebook";
		String username = "test";
		String password = "123aBc456";
		int seqNum = 0;
		String msg = messageToSend(domain,username,password,"0",seqNum);
		
		// Call savePassword method on server
		String saveResponse = pm.savePassword(msg);

		// Analyse the correctness of the answer
		byte[] responseTest = RSAMethods.decipher(saveResponse.split("-")[0],cliPrivKey);
		String responseTestStr = new String(responseTest, "UTF-8");
		Assert.assertEquals("Password Saved", responseTestStr);
	}

	@Test
	public void savePasswordConfidentialityTest() throws RemoteException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException, KeyStoreException, CertificateException {
		
		// Creation of the server and registration
		PasswordManager pm = new PasswordManager(8080);
		String responseRegister = pm.registerUser(byteToString(cliPubKey.getEncoded()), 
				DigitalSignature.getSignature(cliPubKey.getEncoded(),cliPrivKey));

		// Set global variables for Secret Key and Server Public Key based on the register
		byte[] secretKeyByte = RSAMethods.decipher(responseRegister.split("-")[2], cliPrivKey);
		String secretKeyStr = new String(secretKeyByte, "UTF-8");
		secretKey = new SecretKeySpec(stringToByte(secretKeyStr), 0, stringToByte(secretKeyStr).length, "HmacMD5");
		servPubKey = getServerPublicKey(responseRegister.split("-")[0]);
		
		// Simulate the request from client
		String domain = "facebook";
		String username = "test";
		String password = "123aBc456";
		int seqNum = 0;
		String msg = messageToSend(domain,username,password,"0",seqNum);
		
		// Call savePassword method on server
		String saveResponse = pm.savePassword(msg);

		// Check the confientiality of the answer
		Assert.assertNotSame("Passowrd Saved", saveResponse.split("-")[0]);

		// Analyse yet the correctness of the answer
		byte[] responseTest = RSAMethods.decipher(saveResponse.split("-")[0],cliPrivKey);
		String responseTestStr = new String(responseTest, "UTF-8");
		Assert.assertEquals("Password Saved", responseTestStr);
	}
	
	@Test
	public void savePasswordManInTheMiddleTest() throws RemoteException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException, KeyStoreException, CertificateException {
		
		// Creation of the server and registration
		PasswordManager pm = new PasswordManager(8080);
		String responseRegister = pm.registerUser(byteToString(cliPubKey.getEncoded()), 
				DigitalSignature.getSignature(cliPubKey.getEncoded(),cliPrivKey));

		// Set global variables for Secret Key and Server Public Key based on the register
		byte[] secretKeyByte = RSAMethods.decipher(responseRegister.split("-")[2], cliPrivKey);
		String secretKeyStr = new String(secretKeyByte, "UTF-8");
		secretKey = new SecretKeySpec(stringToByte(secretKeyStr), 0, stringToByte(secretKeyStr).length, "HmacMD5");
		servPubKey = getServerPublicKey(responseRegister.split("-")[0]);
		
		// Simulate the request from client
		String domain = "facebook";
		String username = "test";
		String password = "123aBc456";
		int seqNum = 0;
		String msg = messageToSend(domain,username,password,"0",seqNum);
		
		// Simulate a Man-In-The-Middle attack by changing the content of message
		StringBuilder newMsg = new StringBuilder(msg);
		newMsg.insert(4, "a");
		
		// Call savePassword method on server
		String saveResponse = pm.savePassword(newMsg.toString());

		// Check the integrity of the server
		Assert.assertEquals("Error", saveResponse.split("-")[0]);
	}
	
	@Test
	public void savePasswordReplayAttackTest() throws RemoteException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException, KeyStoreException, CertificateException {
		
		// Creation of the server and registration
		PasswordManager pm = new PasswordManager(8080);
		String responseRegister = pm.registerUser(byteToString(cliPubKey.getEncoded()), 
				DigitalSignature.getSignature(cliPubKey.getEncoded(),cliPrivKey));

		// Set global variables for Secret Key and Server Public Key based on the register
		byte[] secretKeyByte = RSAMethods.decipher(responseRegister.split("-")[2], cliPrivKey);
		String secretKeyStr = new String(secretKeyByte, "UTF-8");
		secretKey = new SecretKeySpec(stringToByte(secretKeyStr), 0, stringToByte(secretKeyStr).length, "HmacMD5");
		servPubKey = getServerPublicKey(responseRegister.split("-")[0]);
		
		// Simulate the request from client
		String domain = "facebook";
		String username = "test";
		String password = "123aBc456";
		int seqNum = 0;
		String msg = messageToSend(domain,username,password,"0",seqNum);
		
		// Simulate a Replay Attack by sending the same message twice
		pm.savePassword(msg);
		String saveResponse2 = pm.savePassword(msg.toString()); // Replay attack by sending msg twice
		
		// Check the way server deals with freshness of messages
		byte[] responseTest = RSAMethods.decipher(saveResponse2.split("-")[0],cliPrivKey);
		String responseTestStr = new String(responseTest, "UTF-8");
		Assert.assertEquals("Error", responseTestStr);
	}
	
	// RETRIEVE PASSWORD TESTS
	
	@Test
	public void retrievePasswordTest() throws RemoteException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException, KeyStoreException, CertificateException {
		
		// Creation of the server and registration
		PasswordManager pm = new PasswordManager(8080);
		String responseRegister = pm.registerUser(byteToString(cliPubKey.getEncoded()),
				DigitalSignature.getSignature(cliPubKey.getEncoded(),cliPrivKey));
		
		// Set global variables for Secret Key and Server Public Key based on the register
		byte[] secretKeyByte = RSAMethods.decipher(responseRegister.split("-")[2], cliPrivKey);
		String secretKeyStr = new String(secretKeyByte, "UTF-8");
		secretKey = new SecretKeySpec(stringToByte(secretKeyStr), 0, stringToByte(secretKeyStr).length, "HmacMD5");
		servPubKey = getServerPublicKey(responseRegister.split("-")[0]);
		
		// Simulate the save request from client
		String domain = "facebook";
		String username = "test";
		String password = "123aBc456";
		int seqNum = 0;
		String msg = messageToSend(domain,username,password,"0",seqNum);
		
		// Call savePassword method on server
		pm.savePassword(msg);
		
		// Simulate the retrieve request from client
		seqNum = 1;
		msg = messageToSend(domain,username,"","1",seqNum);

		// Call retrievePassword method on server
		String retrieveResponse = pm.retrievePassword(msg);
		
		// Analyse the correctness of the answer
		byte[] responseTest = RSAMethods.decipher(retrieveResponse.split("-")[0],cliPrivKey);
		String responseTestStr = new String(responseTest, "UTF-8");
		Assert.assertEquals(password, responseTestStr);
	}

	@Test
	public void retrievePasswordConfidentialityTest() throws RemoteException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException, KeyStoreException, CertificateException {
		
		// Creation of the server and registration
		PasswordManager pm = new PasswordManager(8080);
		String responseRegister = pm.registerUser(byteToString(cliPubKey.getEncoded()),
				DigitalSignature.getSignature(cliPubKey.getEncoded(),cliPrivKey));

		// Set global variables for Secret Key and Server Public Key based on the register
		byte[] secretKeyByte = RSAMethods.decipher(responseRegister.split("-")[2], cliPrivKey);
		String secretKeyStr = new String(secretKeyByte, "UTF-8");
		secretKey = new SecretKeySpec(stringToByte(secretKeyStr), 0, stringToByte(secretKeyStr).length, "HmacMD5");
		servPubKey = getServerPublicKey(responseRegister.split("-")[0]);
		
		// Simulate the save request from client
		String domain = "facebook";
		String username = "test";
		String password = "123aBc456";
		int seqNum = 0;
		String msg = messageToSend(domain,username,password,"0",seqNum);
		
		// Call savePassword method on server
		pm.savePassword(msg);
		
		// Simulate the retrieve request from client
		seqNum = 1;
		msg = messageToSend(domain,username,"","1",seqNum);

		// Call retrievePassword method on server
		String retrieveResponse = pm.retrievePassword(msg);
		
		// Check the confientiality of the answer
		Assert.assertNotSame(password, retrieveResponse.split("-")[0]);

		// Analyse the correctness of the answer
		byte[] responseTest = RSAMethods.decipher(retrieveResponse.split("-")[0],cliPrivKey);
		String responseTestStr = new String(responseTest, "UTF-8");
		Assert.assertEquals(password, responseTestStr);
	}
	
	@Test
	public void retrievePasswordManInTheMiddleTest() throws RemoteException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException, KeyStoreException, CertificateException {
		
		// Creation of the server and registration
		PasswordManager pm = new PasswordManager(8080);
		String responseRegister = pm.registerUser(byteToString(cliPubKey.getEncoded()), 
				DigitalSignature.getSignature(cliPubKey.getEncoded(),cliPrivKey));

		// Set global variables for Secret Key and Server Public Key based on the register
		byte[] secretKeyByte = RSAMethods.decipher(responseRegister.split("-")[2], cliPrivKey);
		String secretKeyStr = new String(secretKeyByte, "UTF-8");
		secretKey = new SecretKeySpec(stringToByte(secretKeyStr), 0, stringToByte(secretKeyStr).length, "HmacMD5");
		servPubKey = getServerPublicKey(responseRegister.split("-")[0]);
		
		// Simulate the save request from client
		String domain = "facebook";
		String username = "test";
		String password = "123aBc456";
		int seqNum = 0;
		String msg = messageToSend(domain,username,password,"0",seqNum);

		// Call savePassword method on server
		pm.savePassword(msg);
		
		// Simulate the retrieve request from client
		seqNum = 1;
		msg = messageToSend(domain,username,"","1",seqNum);

		//Simulate a Man-In-The-Middle attack by changing the content of message
		StringBuilder newMsg = new StringBuilder(msg);
		newMsg.insert(4, "a");
		
		// Call retrievePassword method on server
		String retrieveResponse = pm.retrievePassword(newMsg.toString());
		
		// Check the integrity of the server
		Assert.assertEquals("Error", retrieveResponse.split("-")[0]);
	}
	
	@Test
	public void retrievePasswordReplayAttackTest() throws RemoteException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException, KeyStoreException, CertificateException {
		
		// Simulate the save request from client
		PasswordManager pm = new PasswordManager(8080);
		String responseRegister = pm.registerUser(byteToString(cliPubKey.getEncoded()), 
				DigitalSignature.getSignature(cliPubKey.getEncoded(),cliPrivKey));

		// Set global variables for Secret Key and Server Public Key based on the register
		byte[] secretKeyByte = RSAMethods.decipher(responseRegister.split("-")[2], cliPrivKey);
		String secretKeyStr = new String(secretKeyByte, "UTF-8");
		secretKey = new SecretKeySpec(stringToByte(secretKeyStr), 0, stringToByte(secretKeyStr).length, "HmacMD5");
		servPubKey = getServerPublicKey(responseRegister.split("-")[0]);
		
		// Simulate the save request from client
		String domain = "facebook";
		String username = "test";
		String password = "123aBc456";
		int seqNum = 0;
		String msg = messageToSend(domain,username,password,"0",seqNum);

		// Call savePassword method on server
		pm.savePassword(msg);

		// Simulate the retrieve request from client
		seqNum = 1;
		msg = messageToSend(domain,username,"","1",seqNum);

		// Simulate a Replay Attack by sending the same message twice
		pm.retrievePassword(msg);
		String retrieveResponse2 = pm.retrievePassword(msg);
		
		// Check the way server deals with freshness of messages
		byte[] responseTest = RSAMethods.decipher(retrieveResponse2.split("-")[0],cliPrivKey);
		String responseTestStr = new String(responseTest, "UTF-8");
		Assert.assertEquals("Error", responseTestStr);
	}
	
	///////////////////////// SUPPORT METHODS /////////////////////////
	
	public synchronized String messageToSend(String domain, String username, String pass, String timestamp, int seqNum) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, SignatureException, IOException, KeyStoreException, UnrecoverableKeyException, CertificateException {
		String publicKey = byteToString(cliPubKey.getEncoded());

		byte[] c_domain = RSAMethods.cipherPubKeyCliNoPadding(domain, cliPubKey);
		byte[] c_username = RSAMethods.cipherPubKeyCliNoPadding(username, cliPubKey);
		byte[] c_timestamp = RSAMethods.cipherPubKeyCliPadding(timestamp, servPubKey);

		String send_domain = byteToString(c_domain);
		String send_username = byteToString(c_username);
		String send_timestamp = byteToString(c_timestamp);
		String message = "";

		if((!pass.equals(""))&&(!timestamp.equals(""))) {
			// For GetTimestamps or receivePassword messages
			byte[] c_password = RSAMethods.cipherPubKeyCliPadding(pass, cliPubKey);
			String send_password = byteToString(c_password);
			message = publicKey + "-" + String.valueOf(seqNum+1) + "-" + byteToString(RSAMethods.cipherPubKeyCliPadding(byteToString(secretKey.getEncoded()), servPubKey)) + "-" + send_domain + "-" + send_username + "-" + send_password + "-" + send_timestamp;
		}
		else {
			message = publicKey + "-" + String.valueOf(seqNum+1) + "-" + byteToString(RSAMethods.cipherPubKeyCliPadding(byteToString(secretKey.getEncoded()), servPubKey)) + "-" + send_domain + "-" + send_username;
		}

		String signature = DigitalSignature.getSignature(stringToByte(message), cliPrivKey);
		message = message + "-" + signature;
		return message;
	}
	
	public byte[] stringToByte(String str) {
		return DatatypeConverter.parseBase64Binary(str);
	}

	public String byteToString(byte[] byt) {
		return DatatypeConverter.printBase64Binary(byt);
	}

	public PublicKey getServerPublicKey(String key) throws InvalidKeySpecException, NoSuchAlgorithmException {
		byte[] pk = stringToByte(key);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(pk);
		PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
		return publicKey;
	}

	public static void setPublicKey() throws IOException, NoSuchAlgorithmException,InvalidKeySpecException {
		// Read Public Key.
		File filePublicKey = new File(publicKeyPath + 1 +".key");
		FileInputStream fis = new FileInputStream(publicKeyPath + 1 +".key");
		byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
		fis.read(encodedPublicKey);
		fis.close();

		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
		PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

		cliPubKey = publicKey;
	}

	public static PrivateKey getPrivateKey() throws IOException,KeyStoreException,NoSuchAlgorithmException,CertificateException, UnrecoverableKeyException {
		// Read Private Key.

		PrivateKey privateKey = null;
		try {
			FileInputStream fis = new FileInputStream(keyStorePath);

			KeyStore ks = KeyStore.getInstance("JCEKS");

			ks.load(fis,ksPass);

			fis.close();

			privateKey = (PrivateKey) ks.getKey(String.valueOf(1), ksPass);
		}
		catch(Exception e){
			e.printStackTrace();
		}

		return privateKey;
	}
}