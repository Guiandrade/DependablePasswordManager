package pt.ulisboa.ist.sec;

import java.io.IOException;
import java.rmi.RemoteException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
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
	
	@BeforeClass
	public static void keyInitializations() throws NoSuchAlgorithmException {
		KeyPairGenerator keyGenCli = KeyPairGenerator.getInstance("RSA");
        SecureRandom randomCli = SecureRandom.getInstance("SHA1PRNG");
        keyGenCli.initialize(2048, randomCli);
        KeyPair pairCli = keyGenCli.generateKeyPair();
        cliPubKey = pairCli.getPublic();
        cliPrivKey = pairCli.getPrivate();
        
        KeyPairGenerator keyGenServ = KeyPairGenerator.getInstance("RSA");
        SecureRandom randomServ = SecureRandom.getInstance("SHA1PRNG");
        keyGenServ.initialize(2048, randomServ);
        KeyPair pairServ = keyGenServ.generateKeyPair();
        servPubKey = pairServ.getPublic();
        servPrivKey = pairServ.getPrivate();
	}

	///////////////////////// SECURITY TESTS /////////////////////////
	
	// REGISTER USER TESTS
	
	@Test
	public void registerUserTest() throws RemoteException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException, KeyStoreException, CertificateException {
		
		PasswordManager pm = new PasswordManager(8080);
		String response = pm.registerUser(DatatypeConverter.printBase64Binary(cliPubKey.getEncoded()), 
				DigitalSignature.getSignature(cliPubKey.getEncoded(),cliPrivKey));
		
		Assert.assertNotSame(response, "Error: Could not validate signature.");
	}
	
	@Test
	public void registerUserFailingTest() throws RemoteException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException, KeyStoreException, CertificateException {
		
		PasswordManager pm = new PasswordManager(8080);
		String response = pm.registerUser(DatatypeConverter.printBase64Binary(cliPubKey.getEncoded()), 
				DigitalSignature.getSignature(cliPubKey.getEncoded(),servPrivKey));
		
		Assert.assertEquals(response, "Error: Could not validate signature.");
	}
	
	// SAVE PASSWORD TESTS
	
	@Test
	public void savePasswordTest() throws RemoteException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException, KeyStoreException, CertificateException {
		
		PasswordManager pm = new PasswordManager(8080);
		pm.registerUser(byteToString(cliPubKey.getEncoded()), 
				DigitalSignature.getSignature(cliPubKey.getEncoded(),cliPrivKey));
		
		String domain = "facebook";
		String username = "test";
		String password = "123aBc456";
		int seqNum = 0;
		
		String msg = messageToSend(domain,username,password,"0",seqNum);
		
		String saveResponse = pm.savePassword(msg);
		
		byte[] responseTest = RSAMethods.decipher(saveResponse.split("-")[0],cliPrivKey);
		String responseTestStr = new String(responseTest, "UTF-8");
		
		Assert.assertEquals("Password Saved", responseTestStr);
	}
	
	@Test
	public void savePasswordManInTheMiddleTest() throws RemoteException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException, KeyStoreException, CertificateException {
		
		PasswordManager pm = new PasswordManager(8080);
		pm.registerUser(byteToString(cliPubKey.getEncoded()), 
				DigitalSignature.getSignature(cliPubKey.getEncoded(),cliPrivKey));
		
		String domain = "facebook";
		String username = "test";
		String password = "123aBc456";
		int seqNum = 0;
		
		String msg = messageToSend(domain,username,password,"0",seqNum);
		
		StringBuilder newMsg = new StringBuilder(msg);
		newMsg.insert(4, "a"); //Man in the middle changing the content of message
		
		String saveResponse = pm.savePassword(newMsg.toString());
		
		Assert.assertEquals("Error", saveResponse.split("-")[0]);
	}
	
	@Test
	public void savePasswordReplayAttackTest() throws RemoteException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException, KeyStoreException, CertificateException {
		
		PasswordManager pm = new PasswordManager(8080);
		pm.registerUser(byteToString(cliPubKey.getEncoded()), 
				DigitalSignature.getSignature(cliPubKey.getEncoded(),cliPrivKey));
		
		String domain = "facebook";
		String username = "test";
		String password = "123aBc456";
		int seqNum = 0;
		
		String msg = messageToSend(domain,username,password,"0",seqNum);
		
		pm.savePassword(msg);
		String saveResponse2 = pm.savePassword(msg.toString()); // Replay attack by sending msg twice
		
		byte[] responseTest = RSAMethods.decipher(saveResponse2.split("-")[0],cliPrivKey);
		String responseTestStr = new String(responseTest, "UTF-8");
		
		Assert.assertEquals("Error", responseTestStr);
	}
	
	// RETRIEVE PASSWORD TESTS
	
	@Test
	public void retrievePasswordTest() throws RemoteException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException, KeyStoreException, CertificateException {
		
		PasswordManager pm = new PasswordManager(8080);
		pm.registerUser(byteToString(cliPubKey.getEncoded()), 
				DigitalSignature.getSignature(cliPubKey.getEncoded(),cliPrivKey));
		
		String domain = "facebook";
		String username = "test";
		String password = "123aBc456";
		int seqNum = 0;
		
		String msg = messageToSend(domain,username,password,"0",seqNum);
		pm.savePassword(msg);
		
		seqNum = 1;
		
		msg = messageToSend(domain,username,"","1",seqNum);
		String retrieveResponse = pm.retrievePassword(msg);
		
		byte[] responseTest = RSAMethods.decipher(retrieveResponse.split("-")[0],cliPrivKey);
		String responseTestStr = new String(responseTest, "UTF-8");
		
		Assert.assertEquals(password, responseTestStr);
	}
	
	@Test
	public void retrievePasswordManInTheMiddleTest() throws RemoteException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException, KeyStoreException, CertificateException {
		
		PasswordManager pm = new PasswordManager(8080);
		pm.registerUser(byteToString(cliPubKey.getEncoded()), 
				DigitalSignature.getSignature(cliPubKey.getEncoded(),cliPrivKey));
		
		String domain = "facebook";
		String username = "test";
		String password = "123aBc456";
		int seqNum = 0;
		
		String msg = messageToSend(domain,username,password,"0",seqNum);
		pm.savePassword(msg);
		
		seqNum = 1;
		
		msg = messageToSend(domain,username,"","1",seqNum);
		StringBuilder newMsg = new StringBuilder(msg);
		newMsg.insert(4, "a"); //Man in the middle changing the content of message
		
		String retrieveResponse = pm.retrievePassword(newMsg.toString());
		
		Assert.assertEquals("Error", retrieveResponse.split("-")[0]);
	}
	
	@Test
	public void retrievePasswordReplayAttackTest() throws RemoteException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException, KeyStoreException, CertificateException {
		
		PasswordManager pm = new PasswordManager(8080);
		pm.registerUser(byteToString(cliPubKey.getEncoded()), 
				DigitalSignature.getSignature(cliPubKey.getEncoded(),cliPrivKey));
		
		String domain = "facebook";
		String username = "test";
		String password = "123aBc456";
		int seqNum = 0;
		
		String msg = messageToSend(domain,username,password,"0",seqNum);
		pm.savePassword(msg);
		
		seqNum = 1;
		
		msg = messageToSend(domain,username,"","1",seqNum);
		pm.retrievePassword(msg);
		String retrieveResponse2 = pm.retrievePassword(msg);
		
		byte[] responseTest = RSAMethods.decipher(retrieveResponse2.split("-")[0],cliPrivKey);
		String responseTestStr = new String(responseTest, "UTF-8");
		
		Assert.assertEquals("Error", responseTestStr);
	}
	
	///////////////////////// REPLICATION TESTS /////////////////////////
	
	//to do
	
	///////////////////////// SUPPORT METHODS /////////////////////////
	
	public synchronized String messageToSend(String domain, String username, String pass, String timestamp, int seqNum) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, SignatureException, IOException, KeyStoreException, UnrecoverableKeyException, CertificateException {
		String publicKey = byteToString(cliPubKey.getEncoded());

		byte[] c_domain = RSAMethods.cipherPubKeyCliNoPadding(domain, cliPubKey);
		byte[] c_username = RSAMethods.cipherPubKeyCliNoPadding(username, cliPubKey);
		byte[] c_timestamp = RSAMethods.cipherPubKeyCliPadding(timestamp, cliPubKey);

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
}