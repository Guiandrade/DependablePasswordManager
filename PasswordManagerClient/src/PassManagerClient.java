import java.rmi.Naming;

public class PassManagerClient{

	private PassManagerInterface stub;
	private String key;

	public PassManagerClient(){}

	public void setup(){

		try {
			this.stub = (PassManagerInterface) Naming.lookup("rmi://localhost/pm");
			String response = stub.startCommunication();
			System.out.println("Response from Server: "+response);  	            

		} catch (Exception e) {
			System.err.println("Client exception: " + e.toString());
			e.printStackTrace();
		}
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
