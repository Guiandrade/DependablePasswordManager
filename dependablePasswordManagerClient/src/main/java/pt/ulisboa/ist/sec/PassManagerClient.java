package pt.ulisboa.ist.sec;


import java.rmi.Naming;

public class PassManagerClient{

	private PassManagerInterface stub;
	private String key;

	public PassManagerClient(){}

	public void setup(){
		
		PassManagerInterface passManagerInt = null;
		try{
			passManagerInt = (PassManagerInterface) Naming.lookup("//localhost:8081/PasswordManager");
			String response = passManagerInt.startCommunication();
			System.out.println("Response from Server: "+response);  	
		}
		catch(Exception e) {System.out.println("Lookup: " + e.getMessage());}
	}

	public PassManagerInterface getStub() {
		return stub;
	}

	public String getKey() {
		return key;
	}

	public void setKey(String key) {
		this.key = key;
	}

}
