package ids;


import java.util.Timer;
import java.util.TimerTask;



/* Thread che esegue il retract dei pacchetti nella KB per migliorare le prestazioni*/
public class RetractTimer {

	class Retract extends TimerTask {
	    public void run() {
 				
	    	analyzer.retractPackets();
  					
	    }

	}	
	private long delay = 0;
	
	private Analyzer analyzer;
	
	private Timer timer = new Timer();

	public RetractTimer(int seconds,Analyzer analyzer) {
		this.analyzer = analyzer;
		timer.schedule(new Retract(), delay, seconds*1000);
        System.out.println("retractTimer schedulato ogni " + new Integer(seconds));
		  
	}

	
	 
	
	
	  


	public Analyzer getAnalyzer() {
		return analyzer;
	}


	public void setAnalyzer(Analyzer analyzer) {
		this.analyzer = analyzer;
	}


}
