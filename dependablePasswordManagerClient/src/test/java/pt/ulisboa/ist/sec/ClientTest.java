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
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

public class ClientTest {
	
	private static PublicKey cliPubKey;
	private static PrivateKey cliPrivKey;
	private static PublicKey servPubKey;
	private static PrivateKey servPrivKey;
	private static SecretKey secretKey;
	private ConcurrentHashMap<PassManagerInterface,SecretKey> serversList = new ConcurrentHashMap<PassManagerInterface,SecretKey>();
	private static String publicKeyPath = "../keyStore/security/publicKeys/publickey";
	private static String keyStorePath = "../keyStore/security/keyStore/keystore.jce";
	private static char[] ksPass = "sec".toCharArray();
	
	@BeforeClass
	public static void keyInitializations() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, UnrecoverableKeyException, KeyStoreException, CertificateException {
		setPublicKey();
		cliPrivKey = getPrivateKey();
		
        KeyPairGenerator keyGenServ = KeyPairGenerator.getInstance("RSA");
        SecureRandom randomServ = SecureRandom.getInstance("SHA1PRNG");
        keyGenServ.initialize(2048, randomServ);
        KeyPair pairServ = keyGenServ.generateKeyPair();
        servPubKey = pairServ.getPublic();
        servPrivKey = pairServ.getPrivate();
        
        KeyGenerator keygen = KeyGenerator.getInstance("HmacMD5");
		secretKey = keygen.generateKey();
	}

	///////////////////////// SECURITY TESTS /////////////////////////
	
	// REGISTER USER TESTS
	
	@Test
	public void registerUserTest() throws RemoteException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException, KeyStoreException, CertificateException {
		
		// Creation of the client
		PassManagerClient client = new PassManagerClient(1,"sec");
		
		// Simulation of the response message from server to the register request from client
		String messageRecievedByServer = "publicKey";
		String msgRecieved = messageToSend("Register");
		String signature = DigitalSignature.getSignature(stringToByte(messageRecievedByServer),cliPrivKey);

		// Call the processRegisterResponse on client
		boolean response = client.processRegisterResponse(msgRecieved, signature,null,true,secretKey);
		
		// Analyse the correctness of the answer
		Assert.assertEquals(true, response);
	}
	
	@Test
	public void registerUserFailingTest() throws RemoteException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException, KeyStoreException, CertificateException {
		
		// Creation of the client
		PassManagerClient client = new PassManagerClient(1,"sec");
		
		// Simulation of the response message from server to the register request from client
		String messageRecievedByServer = "publicKey";
		String msgRecieved = messageToSend("Register");
		
		// Tampering the message
		StringBuilder newMsg = new StringBuilder(msgRecieved);
		newMsg.insert(4, "xasd");
		String signature = DigitalSignature.getSignature(stringToByte(messageRecievedByServer+""),cliPrivKey);

		// Call the processRegisterResponse method on client
		boolean response = client.processRegisterResponse(newMsg.toString(), signature,null,true,secretKey);
		
		// Analyse the correctness of the answer
		Assert.assertEquals(false, response);
		
	}
	
	// SAVE PASSWORD TESTS
	
	@Test
	public void savePasswordTest() throws RemoteException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException, KeyStoreException, CertificateException {
		
		// Creation of the client and dealing with registration process
		PassManagerClient client = new PassManagerClient(1,"sec");
		String messageRecievedByServer = "arg0-arg1-arg2-arg3-arg4-arg5-arg6";
		String msgRecieved = messageToSend("Register");
		String signature = DigitalSignature.getSignature(stringToByte(messageRecievedByServer),cliPrivKey);
		client.processRegisterResponse(msgRecieved, signature,null,true,secretKey);
		client.setPublicKey();

		// Simulation of the response message from server to the save request from client
		msgRecieved = messageToSend("Save");

		// Call the checkSavedPassword method on client
		String response = client.checkSavedPassword(msgRecieved, messageRecievedByServer, null, true, secretKey,0);
		
		// Analyse the correctness of the answer
		Assert.assertEquals("Password Saved",response);
	}

	@Test
	public void savePasswordConfidentialityTest() throws RemoteException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException, KeyStoreException, CertificateException {
		
		// Creation of the client and dealing with registration process
		PassManagerClient client = new PassManagerClient(1,"sec");
		String messageRecievedByServer = "arg0-arg1-arg2-arg3-arg4-arg5-arg6";
		String msgRecieved = messageToSend("Register");
		String signature = DigitalSignature.getSignature(stringToByte(messageRecievedByServer),cliPrivKey);
		client.processRegisterResponse(msgRecieved, signature,null,true,secretKey);
		client.setPublicKey();

		String msgToSend = client.messageToSend("domain", "username", "pass", "0", null, true);
		
		// Analyse the correctness of the answer
		Assert.assertNotSame("domain",msgToSend.split("-")[3]);
		Assert.assertNotSame("username",msgToSend.split("-")[4]);
		Assert.assertNotSame("pass",msgToSend.split("-")[5]);

		byte[] passByte = RSAMethods.decipher(msgToSend.split("-")[5],cliPrivKey);
		String passStr = new String(passByte, "UTF-8");
		Assert.assertEquals("pass",passStr);
	}
	
	@Test
	public void savePasswordManInTheMiddleTest() throws RemoteException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException, KeyStoreException, CertificateException {
		
		// Creation of the client and dealing with registration process
		PassManagerClient client = new PassManagerClient(1,"sec");
		String messageRecievedByServer = "arg0-arg1-arg2-arg3-arg4-arg5-arg6";
		String msgRecieved = messageToSend("Register");
		String signature = DigitalSignature.getSignature(stringToByte(messageRecievedByServer),cliPrivKey);
		client.processRegisterResponse(msgRecieved, signature,null,true,secretKey);
		client.setPublicKey();
		
		// Simulation of the response message from server to the save request from client
		msgRecieved = messageToSend("Save");

		// Simulate a Man-In-The-Middle attack by changing the content of message
		StringBuilder newMsg = new StringBuilder(msgRecieved);
		newMsg.insert(4, "xasd");

		// Call the checkSavedPassword method on client
		String response = client.checkSavedPassword(newMsg.toString(), messageRecievedByServer, null, true, secretKey, 0);
		
		// Check the integrity of the client
		Assert.assertEquals("Error",response);
	}
	
	@Test
	public void savePasswordReplayAttackTest() throws RemoteException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException, KeyStoreException, CertificateException {
		
		// Creation of the client and dealing with registration process
		PassManagerClient client = new PassManagerClient(1,"sec");
		String messageRecievedByServer = "arg0-arg1-arg2-arg3-arg4-arg5-arg6";
		String msgRecieved = messageToSend("Register");
		String signature = DigitalSignature.getSignature(stringToByte(messageRecievedByServer),cliPrivKey);
		client.processRegisterResponse(msgRecieved, signature,null,true,secretKey);
		client.setPublicKey();
		
		// Simulation of the response message from server to the save request from client
		msgRecieved = messageToSend("Save");

		// Simulate a Replay Attack by calling checkSavedPassword method twice
		client.checkSavedPassword(msgRecieved, messageRecievedByServer, null, true, secretKey, 0);
		String response = client.checkSavedPassword(msgRecieved, messageRecievedByServer, null, true, secretKey, 1);
		
		// Check the way client deals with freshness of messages
		Assert.assertEquals("Error: Could not validate seqNum",response);
	}
	
	// RETRIEVE PASSWORD TESTS
	
	@Test
	public void retrievePasswordTest() throws RemoteException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException, KeyStoreException, CertificateException {
		
		// Creation of the client and dealing with registration process
		PassManagerClient client = new PassManagerClient(1,"sec");
		String messageRecievedByServer = "arg0-arg1-arg2-arg3-arg4";
		String msgRecieved = messageToSend("Register");
		String signature = DigitalSignature.getSignature(stringToByte(messageRecievedByServer),cliPrivKey);
		client.processRegisterResponse(msgRecieved, signature,null,true,secretKey);
		client.setPublicKey();
		
		// Simulation of the response message from server to the retrieve request from client
		msgRecieved = messageToSend("Retrieve");

		// Call the checkRetrievedPassword method on client
		String response = client.checkRetrievedPassword(msgRecieved, messageRecievedByServer, null, true, secretKey, 0);
		
		// Analyse the correctness of the answer
		Assert.assertEquals("test : test",response);
	}

	@Test
	public void retrievePasswordConfidentialityTest() throws RemoteException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException, KeyStoreException, CertificateException {
		
		// Creation of the client and dealing with registration process
		PassManagerClient client = new PassManagerClient(1,"sec");
		String messageRecievedByServer = "arg0-arg1-arg2-arg3-arg4-arg5-arg6";
		String msgRecieved = messageToSend("Register");
		String signature = DigitalSignature.getSignature(stringToByte(messageRecievedByServer),cliPrivKey);
		client.processRegisterResponse(msgRecieved, signature,null,true,secretKey);
		client.setPublicKey();

		String msgToSend = client.messageToSend("domain", "username", "", "0", null, true);
		
		// Analyse the correctness of the answer
		Assert.assertNotSame("domain",msgToSend.split("-")[3]);
		Assert.assertNotSame("username",msgToSend.split("-")[4]);
	}
	
	@Test
	public void retrievePasswordManInTheMiddleTest() throws RemoteException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException, KeyStoreException, CertificateException {
		
		// Creation of the client and dealing with registration process
		PassManagerClient client = new PassManagerClient(1,"sec");
		String messageRecievedByServer = "arg0-arg1-arg2-arg3-arg4";
		String msgRecieved = messageToSend("Register");
		String signature = DigitalSignature.getSignature(stringToByte(messageRecievedByServer),cliPrivKey);
		client.processRegisterResponse(msgRecieved, signature,null,true,secretKey);
		client.setPublicKey();
		
		// Simulation of the response message from server to the retrieve request from client
		msgRecieved = messageToSend("Retrieve");

		// Simulate a Man-In-The-Middle attack by changing the content of message
		StringBuilder newMsg = new StringBuilder(msgRecieved);
		newMsg.insert(4, "xasd");

		// Call the checkRetrievedPassword method on client
		String response = client.checkRetrievedPassword(newMsg.toString(), messageRecievedByServer, null, true, secretKey, 0);
		
		// Check the integrity of the client
		Assert.assertEquals("Error",response);
	}
	
	@Test
	public void retrievePasswordReplayAttackTest() throws RemoteException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException, KeyStoreException, CertificateException {
		
		// Creation of the client and dealing with registration process
		PassManagerClient client = new PassManagerClient(1,"sec");
		String messageRecievedByServer = "arg0-arg1-arg2-arg3-arg4";
		String msgRecieved = messageToSend("Register");
		String signature = DigitalSignature.getSignature(stringToByte(messageRecievedByServer),cliPrivKey);
		client.processRegisterResponse(msgRecieved, signature,null,true,secretKey);
		client.setPublicKey();
		
		// Simulation of the response message from server to the retrieve request from client
		msgRecieved = messageToSend("Retrieve");

		// Simulate a Replay Attack by calling checkRetrievedPassword method twice
		client.checkRetrievedPassword(msgRecieved, messageRecievedByServer, null, true, secretKey, 0);
		String response = client.checkRetrievedPassword(msgRecieved, messageRecievedByServer, null, true, secretKey, 1);
		
		// Check the way client deals with freshness of messages
		Assert.assertEquals("Error",response);
	}
	
	///////////////////////// SUPPORT METHODS /////////////////////////
	
	public synchronized String messageToSend(String type) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, SignatureException, IOException, KeyStoreException, UnrecoverableKeyException, CertificateException {
		String publicKey = byteToString(servPubKey.getEncoded());
		
		String password = "test";
		String timestamp = "test";
		String message = "";
		String signature = "";
		
		byte[] c_timestamp = RSAMethods.cipherPubKeyCliPadding(timestamp, cliPubKey);
		byte[] c_password = RSAMethods.cipherPubKeyCliPadding(password, cliPubKey);
		byte[] c_secretKey = RSAMethods.cipherPubKeyCliPadding(byteToString(secretKey.getEncoded()), cliPubKey);
		
		String sendTimestamp = byteToString(c_timestamp);
		String sendPassword = byteToString(c_password);
		String sendSecretKey = byteToString(c_secretKey);
		
		if(type.equals("Register")) {
			String messageRecievedByServer = "publicKey";
			signature = DigitalSignature.getSignature(stringToByte(messageRecievedByServer),cliPrivKey);
			String seqNum = "0";
			byte[] c_seqNum = RSAMethods.cipherPubKeyCliPadding(seqNum, cliPubKey);
			String sendSeqNum = byteToString(c_seqNum);
			String msg = publicKey + "-" + sendSeqNum + "-" + sendSecretKey + "-" + signature;
			String mac = RSAMethods.generateMAC(secretKey, msg);
			message = msg + "-" + mac;
			return message;
		}
		else {
			String seqNum = "1";
			String responseStr = "";
			String msg = "";
			if(type.equals("Save")) {
				String messageRecievedByServer = "arg0-arg1-arg2-arg3-arg4-arg5-arg6";
				signature = DigitalSignature.getSignature(stringToByte(messageRecievedByServer),cliPrivKey);
				String response = "Password Saved";
				byte[] responseByte = RSAMethods.cipherPubKeyCliPadding(response,cliPubKey);
				responseStr = byteToString(responseByte);
				msg = responseStr + "-" + seqNum + "-" + signature;
				
			}
			else if(type.equals("Retrieve")) {
				String messageRecievedByServer = "arg0-arg1-arg2-arg3-arg4";
				signature = DigitalSignature.getSignature(stringToByte(messageRecievedByServer),cliPrivKey);
				responseStr = sendPassword;
				msg = responseStr + "-" + seqNum + "-" + sendTimestamp + "-" + signature;
			}
			String mac = RSAMethods.generateMAC(secretKey, msg);
			message = msg + "-" + mac;
			return message;
		}		
	}
	
	public byte[] stringToByte(String str) {
		return DatatypeConverter.parseBase64Binary(str);
	}

	public String byteToString(byte[] byt) {
		return DatatypeConverter.printBase64Binary(byt);
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