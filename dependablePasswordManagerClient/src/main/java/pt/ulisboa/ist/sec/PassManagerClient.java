package pt.ulisboa.ist.sec;

import java.rmi.Naming;
import java.security.*;
import java.io.*;
import java.security.spec.*;
import java.util.Base64;

public class PassManagerClient{

	private PassManagerInterface passManagerInt;
	private String pubKey;
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

	public String getPublicKey() {
		return pubKey;
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

				 pubKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());
	}

	public String getPrivateKey() throws IOException, NoSuchAlgorithmException,InvalidKeySpecException {
				// Read Private Key.
				File filePrivateKey = new File(privateKeyPath + id+ ".key");
				FileInputStream fis = new FileInputStream(privateKeyPath + id+ ".key");
				byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
				fis.read(encodedPrivateKey);
				fis.close();

				KeyFactory keyFactory = KeyFactory.getInstance("RSA");
				PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
			 	PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

				return Base64.getEncoder().encodeToString(privateKey.getEncoded());
	}

	public int getId() {
		return id;
	}

	public void setId(int id) {
		this.id = id;
	}

}
