package pt.ulisboa.ist.sec;

public class Combination {

	private String attribute1;
	private String attribute2;

	public Combination(String x, String  y) {
		// x is domain or secretNum and y is username or nounce
		attribute1 = x;
		attribute2 = y;
	}

	public String getDomain() {
		return attribute1;
	}

	public String  getUsername() {
		return attribute2;
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
