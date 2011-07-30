package ids;
import java.io.IOException;

import jpcap.*;
import jpcap.packet.Packet;

import jpcap.PacketReceiver;

class Sniffer implements PacketReceiver{
	
	private Analyzer analyzer;
	
	/* avvio thread sniffer */
	public void start() {
		
		System.out.println("start sniffer");
		
		try{
			/* apro interfaccia attiva */
			JpcapCaptor jpcap=JpcapCaptor.openDevice(JpcapCaptor.getDeviceList()[1],1000,false,20);
			/* filtro solo pacchetti tcp */
			jpcap.setFilter("tcp", true);
			/* inizio a raccogliere pacchetti*/
			jpcap.loopPacket(-1, this);
			
		}
		catch (java.io.IOException e) {
			System.out.println("I/O Exception");
		}
				
		
		
	}

	/* legge pacchetti da file */
	public void readFile(String file){
	
		try {
			JpcapCaptor jpcap = JpcapCaptor.openFile(file);
			jpcap.setFilter("tcp", true);
			/* processo pacchetti */
			jpcap.processPacket(-1, this);
			int n = jpcap.received_packets;
			System.out.println("pacchetti letti " + n);
			
			
	} catch (IOException e) {
		
	}
	
}
	
	
	/* 
	 * ogni volta che il sistema riceve un pacchetto questo metodo viene 
	 * chiamato indipendentemente se letto da file o catturato live
	*/
	public void receivePacket(Packet packet) {
		/* asserisce pacchetto come fatto */
		analyzer.assertPacket(packet);
		/* esegue query */
		boolean query = analyzer.query();
		
		if (query){
			System.out.println("scanning rilevato");
			/* ho trovato lo scan esco dall'applicazione :) */
			System.exit(0);
		}
	}
	

	public Analyzer getAnalyzer() {
		return analyzer;
	}
	
	public void setAnalyzer(Analyzer analyzer) {
		this.analyzer = analyzer;
	}


}
