
public class PassManagerClientMain {
	
	public static void main(String[] args) {
		PassManagerClient client = new PassManagerClient();
		client.setup(0); // 0 is default_value for client id
		ClientMenu menu = new ClientMenu();
		while(true){
			menu.display();
		}            	            
	}
}
