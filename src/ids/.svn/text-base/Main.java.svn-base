package ids;
import java.io.FileInputStream;
import java.util.Timer;
import java.util.TimerTask;

import alice.tuprolog.*;

public class Main {


	/* inizializza ambiente JPL */
	public static void init(Prolog engine){
		
		try { 
			Theory kb = new Theory(new FileInputStream("C:/Documents and Settings/TeX/Documenti/IA/ids-with-prolog/ids/kb.pl")); 
			engine.setTheory(kb);
		}
		catch (Exception e) {
			e.printStackTrace();
			
			
		}
		finally {}
	}
	
	
	public static void main(String[] args) {
		
		if(args.length <= 2){
			System.out.println("Usage: kb.pl n_connections file.pcap|sniffer");
		//	System.exit(0);
		}
		

		Prolog engine = new Prolog();
			
		Analyzer analyzer = new Analyzer(engine);
		
		Sniffer sniffer = new Sniffer();
		
		//init(engine);
		sniffer.setAnalyzer(analyzer);
		
		/* cattura pacchettti "live" */
		/*
		System.out.println("avvio sniffer");
		sniffer.start();
		*/
		
		/* legge file pacchetti catturati */
		
		analyzer.initializeKB("/home/p1mps/ids-with-prolog/ids/kb.pl",6);
		//analyzer.initializeKB(args[0],Integer.parseInt(args[1]));
		//sniffer.readFile("/home/p1mps/ids-with-prolog/ids/scan_nmap2.pcap");
		//RetractTimer timer = new RetractTimer(10,analyzer);
		//sniffer.start();

		/*
		if(args[2].equals("sniffer"))
			sniffer.start();
		else
			sniffer.readFile(args[2]);
		*/
		
		analyzer.query();
	}

}
