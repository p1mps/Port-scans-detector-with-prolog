package ids;


import java.util.Timer;
import java.util.TimerTask;




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
        //timer.schedule(new Retract(), seconds*1000);
        System.out.println("ho schedulato");
		/*
		System.out.println("Rectract packets");
	    toolkit = Toolkit.getDefaultToolkit();
	    timer = new Timer();
	    timer.schedule(new Retract(), seconds * 1000);
	    */
	  
	}

	
	 
	
	
	  


	public Analyzer getAnalyzer() {
		return analyzer;
	}


	public void setAnalyzer(Analyzer analyzer) {
		this.analyzer = analyzer;
	}


}
