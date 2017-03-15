package pt.ulisboa.ist.sec;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.SignatureException;
import java.security.InvalidKeyException;
import java.security.spec.*;
import java.io.IOException;
import java.security.PrivateKey;
import javax.xml.bind.DatatypeConverter;

public class DigitalSignature{

	public static boolean verifySignature(byte[] pubKeyClient,byte[] signature,byte[] message) throws NoSuchAlgorithmException, InvalidKeySpecException,InvalidKeyException,SignatureException{
		// verifying a signature
		byte[] data = message;
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(pubKeyClient);
		PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

		Signature rsaForVerify = Signature.getInstance("SHA256withRSA");
		rsaForVerify.initVerify(publicKey);
		rsaForVerify.update(message);
		boolean verifies = rsaForVerify.verify(signature);
		return verifies;
	}

	public static String getSignature(byte[] message,PrivateKey key)  throws IOException, NoSuchAlgorithmException, InvalidKeySpecException,InvalidKeyException,SignatureException{
		byte[] data = message;
		// generating a signature
		Signature rsaForSign = Signature.getInstance("SHA256withRSA");
		rsaForSign.initSign(key);
		rsaForSign.update(data);
		byte[] signature = rsaForSign.sign();
		return byteToString(signature);
	}

	public static String byteToString(byte[] byt) {
		return DatatypeConverter.printBase64Binary(byt);
	}

	public static byte[] stringToByte(String str) {
		return DatatypeConverter.parseBase64Binary(str);
	}


}
