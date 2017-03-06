import java.util.Scanner;

public class ClientMenu {

	private Scanner input = new Scanner(System.in);

	public void display() {
		System.out.println("----- PasswordManager Client -----");
		System.out.println(
				"Select an option: \n" +
						"  1) Register User\n" +
						"  2) Save Password\n" +
						"  3) Retrieve Password\n" +
						"  4) Exit\n " +
						"----------------------------------"
				);

		int selection = input.nextInt();
		input.nextLine();

		switch (selection) {
		case 1:
			registerUser();
			break;
		case 2:
			savePassword();
			break;
		case 3:
			retrievePassword();
			break;
		case 4:
			exit();
			break;
		default:
			System.out.println("Invalid selection.");
			break;
		}

	}

	public void exit() {
		// Complete with close() -> concludes the current session of commands with the client library.
		System.out.println("Exiting...");
		System.exit(1); 

	}

	public String retrievePassword() {
		System.out.println("retrievePassword!\n");
		return null;

	}

	public void savePassword() {
		System.out.println("savePassword!\n");
	}

	public void registerUser() {
		System.out.println("registerUser!\n");
	}
}