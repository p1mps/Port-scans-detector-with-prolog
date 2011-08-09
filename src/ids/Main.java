package ids;
/* libreria prolog */
import alice.tuprolog.*;


/* classe principale */
public class Main {

	public static void main(String[] args) {

		/* parametri da riga di comando */
		if(args.length <= 2){
			System.out.println("Usage: kb.pl n_connections file.pcap|sniffer seconds_retract_timer");
			System.exit(0);
		}
		
		Prolog engine = new Prolog();
			
		Analyzer analyzer = new Analyzer(engine);
		
		Sniffer sniffer = new Sniffer();
		
		sniffer.setAnalyzer(analyzer);
		
		/* numero connessioni * 2 == numero_porte */
		Integer connCount = Integer.parseInt(args[1]);
		
		/* base di conoscenza prolog */
		String fileKb = args[0];  
				
		/* inizializza ambiente prolog */
		analyzer.initializeKB(fileKb,connCount * 2);
		
		/* avvio retract base di conoscenza per ottimizzare prestazioni */
		if(args[2].equals("sniffer")){
			RetractTimer retractTimer = new RetractTimer(new Integer(args[3]), analyzer);
		}
			
		if (args[2].equals("sniffer")) {
			/* modalità sniffer live */
			sniffer.start();
			
		}
		else
		{
			/* modalità lettura di file di sniffing */	
			sniffer.readFile(args[2]);
			boolean query = analyzer.query();
			if (!query){
				System.out.println("scanning non rilevato");
				System.exit(0);
			}
		}
				
		
	}

}
