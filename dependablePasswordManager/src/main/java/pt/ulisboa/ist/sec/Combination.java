package pt.ulisboa.ist.sec;
import java.util.concurrent.atomic.AtomicInteger;

public class Combination {

	private String attribute1;
	private String attribute2;
	private AtomicInteger timeStamp;

	public Combination(String x, String y){
		attribute1 = x;
		attribute2 = y;
		timeStamp = new AtomicInteger();
	}

	public Combination(String x, String  y,String ts) {
		// x is domain and y is username
		attribute1 = x;
		attribute2 = y;
		int i = Integer.parseInt(ts);
		timeStamp.set(i);
	}

	public String getDomain() {
		return attribute1;
	}

	public String  getUsername() {
		return attribute2;
	}

	public int getTimeStamp(){
		return timeStamp.get();
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
