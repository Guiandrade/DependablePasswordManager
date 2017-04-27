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
        
        KeyGenerator keygen = KeyGenerator.getInstance("HmacMD5");
		secretKey = keygen.generateKey();
	}

	///////////////////////// SECURITY TESTS /////////////////////////
	
	// REGISTER USER TESTS
	
	@Test
	public void registerUserTest() throws RemoteException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException, KeyStoreException, CertificateException {
		
		
	}
	
	@Test
	public void registerUserFailingTest() throws RemoteException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException, KeyStoreException, CertificateException {
		
		
	}
	
	// SAVE PASSWORD TESTS
	
	@Test
	public void savePasswordTest() throws RemoteException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException, KeyStoreException, CertificateException {
		
		
	}
	
	@Test
	public void savePasswordManInTheMiddleTest() throws RemoteException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException, KeyStoreException, CertificateException {
		
		
	}
	
	@Test
	public void savePasswordReplayAttackTest() throws RemoteException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException, KeyStoreException, CertificateException {
		
	
	}
	
	// RETRIEVE PASSWORD TESTS
	
	@Test
	public void retrievePasswordTest() throws RemoteException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException, KeyStoreException, CertificateException {
		
		
	}
	
	@Test
	public void retrievePasswordManInTheMiddleTest() throws RemoteException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException, KeyStoreException, CertificateException {
		
		
	}
	
	@Test
	public void retrievePasswordReplayAttackTest() throws RemoteException, NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException, KeyStoreException, CertificateException {
		
		
	}
	
	///////////////////////// REPLICATION TESTS /////////////////////////
	
	//to do
	
	///////////////////////// SUPPORT METHODS /////////////////////////
	
	public synchronized String messageToSend(String type) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, SignatureException, IOException, KeyStoreException, UnrecoverableKeyException, CertificateException {
		String publicKey = byteToString(servPubKey.getEncoded());
		
		String password = "test";
		String timestamp = "test";
		String messageRecievedByServer = "This is just a test message";
		String seqNum = "0";
		String signature = DigitalSignature.getSignature(stringToByte(messageRecievedByServer),cliPrivKey);
		String message = "";
		
		byte[] c_timestamp = RSAMethods.cipherPubKeyCliNoPadding(timestamp, cliPubKey);
		byte[] c_password = RSAMethods.cipherPubKeyCliPadding(password, cliPubKey);
		byte[] c_seqNum = RSAMethods.cipherPubKeyCliNoPadding(seqNum, cliPubKey);
		byte[] c_secretKey = RSAMethods.cipherPubKeyCliPadding(byteToString(secretKey.getEncoded()), cliPubKey);
		
		String sendSeqNum = byteToString(c_seqNum);
		String sendTimestamp = byteToString(c_timestamp);
		String sendPassword = byteToString(c_password);
		String sendSecretKey = byteToString(c_secretKey);
		
		if(type.equals("Register")) {
			String msg = publicKey + "-" + sendSeqNum + "-" + sendSecretKey + "-" + signature;
			String mac = RSAMethods.generateMAC(secretKey, message);
			message = msg + "-" + mac;
			return message;
		}
		else {
			String responseStr = "";
			if(type.equals("Save")) {
				String response = "response";
				byte[] responseByte = RSAMethods.cipherPubKeyCliPadding(response,cliPubKey);
				responseStr = byteToString(responseByte);
				
			}
			else if(type.equals("Retrieve")) {
				responseStr = sendPassword;
			}
			String msg = responseStr + seqNum + signature;
			String mac = RSAMethods.generateMAC(secretKey, message);
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
}