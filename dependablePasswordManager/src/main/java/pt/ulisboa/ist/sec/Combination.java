package pt.ulisboa.ist.sec;

public class Combination { 

	private byte[] username; 
	private byte[] password; 

	public Combination(byte[] username, byte[]  password) { 
		this.setUsername(username); 
		this.setPassword(password); 
	}

	public byte[] getPassword() {
		return password;
	}

	public void setPassword(byte[] password) {
		this.password = password;
	}

	public byte[]  getUsername() {
		return username;
	}

	public void setUsername(byte[]  username) {
		this.username = username;
	} 



} 