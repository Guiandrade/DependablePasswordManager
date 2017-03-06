import java.rmi.Naming;


public class PassManagerMain {

	public static void main (String[] argv){
		try {
				PasswordManager  passManager = new PasswordManager();
				Naming.rebind("rmi://localhost/pm", passManager);
            	            
				System.out.println("Server ready and awaiting connections!");
				
			} catch (Exception e){
				System.out.println("Server failed :"+ e);
			}
	}
}
