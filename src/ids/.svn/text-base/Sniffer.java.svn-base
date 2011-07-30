package ids;
import java.io.IOException;

import jpcap.*;
import jpcap.packet.Packet;

import jpcap.PacketReceiver;

class Sniffer implements PacketReceiver{
	
	//private Blackboard blackboard;
	
	private Analyzer analyzer;
	
	/* raccoglie pacchetti "live"*/
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
		System.out.println("leggo pacchetti");
		JpcapCaptor jpcap = JpcapCaptor.openFile(file);
		jpcap.setFilter("tcp", true);
		int n = jpcap.received_packets;
		System.out.println("pacchetti ricevuti " + n);
		jpcap.processPacket(-1, this);
		
		//analyzer.query();
		
		
	} catch (IOException e) {
		e.printStackTrace();
	}
	
}
	
	
/* ogni volta che il sistema riceve un pacchetto questo metodo viene chiamato
	indipendentemente se letto da file o catturato live
*/
 
public void receivePacket(Packet packet) {
	
	
	//System.out.println(packet);
	/* asserisce pacchetto come fatto */
	analyzer.assertPacket(packet);
	/* esegue query tcp_scan(X,Y) */
	analyzer.query();
	
	
}
	
	
/*
public Blackboard getBlackboard() {
	return blackboard;
}

public void setBlackboard(Blackboard blackboard) {
	this.blackboard = blackboard;
}
*/

public Analyzer getAnalyzer() {
	return analyzer;
}

public void setAnalyzer(Analyzer analyzer) {
	this.analyzer = analyzer;
}


}
