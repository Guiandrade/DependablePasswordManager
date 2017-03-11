package pt.ulisboa.ist.sec;

public class Combination {

	private String domain;
	private String username;

	public Combination(String domain, String  username) {
		this.setDomain(domain);
		this.setUsername(username);
	}

	public String getDomain() {
		return domain;
	}

	public void setDomain(String domain) {
		this.domain = domain;
	}

	public String  getUsername() {
		return username;
	}

	public void setUsername(String  username) {
		this.username = username;
	}

	public boolean equalsTo(Combination c){
		if (c.getDomain().equals(getDomain()) && c.getUsername().equals(getUsername())){
			return true;
		}
		else{
			return false;
		}
	}



}
