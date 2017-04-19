package pt.ulisboa.ist.sec;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Signature;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.InvalidKeyException;
import java.security.spec.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.PrivateKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;

public class RSAMethods{
	
	public static byte[] stringToByte(String str) {
		return DatatypeConverter.parseBase64Binary(str);
	}

	public static String byteToString(byte[] byt) {
		return DatatypeConverter.printBase64Binary(byt);
	}

	public static byte[] cipherPubKeyCliPadding(String message, PublicKey publicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] c_message = cipher.doFinal(message.getBytes("UTF-8"));
		return c_message;
	}

	public static byte[] cipherPubKeyCliNoPadding(String message, PublicKey publicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
		Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] c_message = cipher.doFinal(message.getBytes("UTF-8"));
		return c_message;
	}

	public static byte[] decipher(String c_message, PrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, IOException {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] message = cipher.doFinal(stringToByte(c_message));
		return message;
	}
	
	public static boolean verifyMAC(SecretKey sk, String mac, String message) throws NoSuchAlgorithmException, InvalidKeyException {
		Mac authenticator = Mac.getInstance(sk.getAlgorithm());
		authenticator.init(sk);
		byte[] msg = message.getBytes();
		byte[] msgAuthenticator = authenticator.doFinal(msg);
		byte[] macToVerify = stringToByte(mac);
		
		String msgAuthenticatorStr = byteToString(msgAuthenticator);
		String macToVerifyStr = byteToString(macToVerify);
		return msgAuthenticatorStr.equals(macToVerifyStr);
	}
}