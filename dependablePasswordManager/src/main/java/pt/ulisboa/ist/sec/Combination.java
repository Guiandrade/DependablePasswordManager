package pt.ulisboa.ist.sec;

public class Combination {

	private String attribute1;
	private String attribute2;

	public Combination(String x, String  y) {
		// x is domain or secretNum and y is username or nounce
		this.setAttribute1(x);
		this.setAttribute2(y);
	}

	public String getDomain() {
		return attribute1;
	}

	public String getSecretNum() {
		return attribute1;
	}

	public String  getUsername() {
		return attribute2;
	}

	public String  getNounce() {
		return attribute2;
	}

	public void setAttribute1(String str) {
		this.attribute1 = str;
	}

	public void setAttribute2(String  str) {
		this.attribute1= str;
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
