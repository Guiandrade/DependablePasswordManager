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
import javax.crypto.NoSuchPaddingException;
import javax.xml.bind.DatatypeConverter;

public class RSAMethods{
	
	public static byte[] stringToByte(String str) {
		return DatatypeConverter.parseBase64Binary(str);
	}

	public static String byteToString(byte[] byt) {
		return DatatypeConverter.printBase64Binary(byt);
	}

	public static byte[] cipher(String message, PublicKey publicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] c_message = cipher.doFinal(message.getBytes("UTF-8"));
		return c_message;
	}

	public static PublicKey getClientPublicKey(String key) throws InvalidKeySpecException, NoSuchAlgorithmException {
		byte[] pk = stringToByte(key);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(pk);
		PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
		return publicKey;
	}
}
