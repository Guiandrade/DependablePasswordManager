


import java.rmi.Naming;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class PassManagerClientMain {
	  public static void main(String[] args) {

	        try {
	            PassManagerInterface stub = (PassManagerInterface) Naming.lookup("rmi://localhost/pm");
	            String response = stub.startCommunication(0);  // 0 is default_value
	            System.out.println("Response from Server: "+response);
	        } catch (Exception e) {
	            System.err.println("Client exception: " + e.toString());
	            e.printStackTrace();
	        }
	    }
	

}
