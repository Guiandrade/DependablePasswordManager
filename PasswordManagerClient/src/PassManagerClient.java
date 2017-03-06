import java.rmi.Naming;

public class PassManagerClient{

	public PassManagerClient(){}

	public void setup(int clientId){
		try {
			PassManagerInterface stub = (PassManagerInterface) Naming.lookup("rmi://localhost/pm");
			String response = stub.startCommunication(clientId);
			System.out.println("Response from Server: "+response);  	            

		} catch (Exception e) {
			System.err.println("Client exception: " + e.toString());
			e.printStackTrace();
		}
	}
}
