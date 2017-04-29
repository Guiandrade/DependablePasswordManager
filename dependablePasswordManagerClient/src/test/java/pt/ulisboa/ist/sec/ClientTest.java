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
		PassManagerClient client = new PassManagerClient(1,"sec");
		
		String messageRecievedByServer = "publicKey";
		String msgRecieved = messageToSend("Register");
		String signature = DigitalSignature.getSignature(stringToByte(messageRecievedByServer),cliPrivKey);
		boolean response = client.processRegisterResponse(msgRecieved, signature,null,true,secretKey);
		
		Assert.assertEquals(true, response);
	}
	
	@Test
	public void registerUserFailingTest() throws RemoteException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException, KeyStoreException, CertificateException {
		PassManagerClient client = new PassManagerClient(1,"sec");
		
		String messageRecievedByServer = "publicKey";
		String msgRecieved = messageToSend("Register");
		
		StringBuilder newMsg = new StringBuilder(msgRecieved);
		newMsg.insert(4, "xasd");
		
		String signature = DigitalSignature.getSignature(stringToByte(messageRecievedByServer+""),cliPrivKey);
		boolean response = client.processRegisterResponse(newMsg.toString(), signature,null,true,secretKey);
		
		Assert.assertEquals(false, response);
		
	}
	
	// SAVE PASSWORD TESTS
	
	@Test
	public void savePasswordTest() throws RemoteException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException, KeyStoreException, CertificateException {
		PassManagerClient client = new PassManagerClient(1,"sec");
		
		String messageRecievedByServer = "arg0-arg1-arg2-arg3-arg4-arg5-arg6";
		String msgRecieved = messageToSend("Register");
		String signature = DigitalSignature.getSignature(stringToByte(messageRecievedByServer),cliPrivKey);
		client.processRegisterResponse(msgRecieved, signature,null,true,secretKey);
		client.setPublicKey();
		
		msgRecieved = messageToSend("Save");
		String response = client.checkSavedPassword(msgRecieved, messageRecievedByServer, null, true, secretKey);
		
		Assert.assertEquals("Password Saved",response);
	}
	
	@Test
	public void savePasswordManInTheMiddleTest() throws RemoteException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException, KeyStoreException, CertificateException {
		PassManagerClient client = new PassManagerClient(1,"sec");
		
		String messageRecievedByServer = "arg0-arg1-arg2-arg3-arg4-arg5-arg6";
		String msgRecieved = messageToSend("Register");
		String signature = DigitalSignature.getSignature(stringToByte(messageRecievedByServer),cliPrivKey);
		client.processRegisterResponse(msgRecieved, signature,null,true,secretKey);
		client.setPublicKey();
		
		msgRecieved = messageToSend("Save");

		StringBuilder newMsg = new StringBuilder(msgRecieved);
		newMsg.insert(4, "xasd");

		String response = client.checkSavedPassword(newMsg.toString(), messageRecievedByServer, null, true, secretKey);
		
		Assert.assertEquals("Error",response);
	}
	
	@Test
	public void savePasswordReplayAttackTest() throws RemoteException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException, KeyStoreException, CertificateException {
		PassManagerClient client = new PassManagerClient(1,"sec");
		
		String messageRecievedByServer = "arg0-arg1-arg2-arg3-arg4-arg5-arg6";
		String msgRecieved = messageToSend("Register");
		String signature = DigitalSignature.getSignature(stringToByte(messageRecievedByServer),cliPrivKey);
		client.processRegisterResponse(msgRecieved, signature,null,true,secretKey);
		client.setPublicKey();
		
		msgRecieved = messageToSend("Save");
		client.checkSavedPassword(msgRecieved, messageRecievedByServer, null, true, secretKey);
		String response = client.checkSavedPassword(msgRecieved, messageRecievedByServer, null, true, secretKey);
		
		Assert.assertEquals("Error: seqNumber not right",response);
	}
	
	// RETRIEVE PASSWORD TESTS
	
	@Test
	public void retrievePasswordTest() throws RemoteException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException, KeyStoreException, CertificateException {
		PassManagerClient client = new PassManagerClient(1,"sec");
		
		String messageRecievedByServer = "arg0-arg1-arg2-arg3-arg4";
		String msgRecieved = messageToSend("Register");
		String signature = DigitalSignature.getSignature(stringToByte(messageRecievedByServer),cliPrivKey);
		client.processRegisterResponse(msgRecieved, signature,null,true,secretKey);
		client.setPublicKey();
		
		msgRecieved = messageToSend("Retrieve");
		String response = client.checkRetrievedPassword(msgRecieved, messageRecievedByServer, null, true, secretKey);
		
		Assert.assertEquals("Your password is : test",response);
	}
	
	@Test
	public void retrievePasswordManInTheMiddleTest() throws RemoteException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException, KeyStoreException, CertificateException {
		PassManagerClient client = new PassManagerClient(1,"sec");
		
		String messageRecievedByServer = "arg0-arg1-arg2-arg3-arg4";
		String msgRecieved = messageToSend("Register");
		String signature = DigitalSignature.getSignature(stringToByte(messageRecievedByServer),cliPrivKey);
		client.processRegisterResponse(msgRecieved, signature,null,true,secretKey);
		client.setPublicKey();
		
		msgRecieved = messageToSend("Retrieve");

		StringBuilder newMsg = new StringBuilder(msgRecieved);
		newMsg.insert(4, "xasd");

		String response = client.checkRetrievedPassword(newMsg.toString(), messageRecievedByServer, null, true, secretKey);
		
		Assert.assertEquals("Error",response);
	}
	
	@Test
	public void retrievePasswordReplayAttackTest() throws RemoteException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException, KeyStoreException, CertificateException {
		PassManagerClient client = new PassManagerClient(1,"sec");
		
		String messageRecievedByServer = "arg0-arg1-arg2-arg3-arg4";
		String msgRecieved = messageToSend("Register");
		String signature = DigitalSignature.getSignature(stringToByte(messageRecievedByServer),cliPrivKey);
		client.processRegisterResponse(msgRecieved, signature,null,true,secretKey);
		client.setPublicKey();
		
		msgRecieved = messageToSend("Retrieve");
		client.checkRetrievedPassword(msgRecieved, messageRecievedByServer, null, true, secretKey);
		String response = client.checkRetrievedPassword(msgRecieved, messageRecievedByServer, null, true, secretKey);
		
		Assert.assertEquals("Error",response);
	}
	
	///////////////////////// REPLICATION TESTS /////////////////////////
	
	//to do
	
	///////////////////////// SUPPORT METHODS /////////////////////////
	
	public synchronized String messageToSend(String type) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, SignatureException, IOException, KeyStoreException, UnrecoverableKeyException, CertificateException {
		String publicKey = byteToString(servPubKey.getEncoded());
		
		String password = "test";
		String timestamp = "test";
		String message = "";
		String signature = "";
		
		byte[] c_timestamp = RSAMethods.cipherPubKeyCliNoPadding(timestamp, cliPubKey);
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
			if(type.equals("Save")) {
				String messageRecievedByServer = "arg0-arg1-arg2-arg3-arg4-arg5-arg6";
				signature = DigitalSignature.getSignature(stringToByte(messageRecievedByServer),cliPrivKey);
				String response = "Password Saved";
				byte[] responseByte = RSAMethods.cipherPubKeyCliPadding(response,cliPubKey);
				responseStr = byteToString(responseByte);
				
			}
			else if(type.equals("Retrieve")) {
				String messageRecievedByServer = "arg0-arg1-arg2-arg3-arg4";
				signature = DigitalSignature.getSignature(stringToByte(messageRecievedByServer),cliPrivKey);
				responseStr = sendPassword;
			}
			String msg = responseStr + "-" + seqNum + "-" + signature;
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