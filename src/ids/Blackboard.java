package ids;
import jpcap.packet.Packet;
import java.util.Vector;

public class Blackboard{
	
	
	private Vector<Packet> packets = new Vector<Packet>();
	
	public synchronized Vector<Packet> read(int n){
		
		Vector<Packet> packets = new Vector<Packet>();
		
		/* ritorna pacchetti dal fondo della coda */
		for (int i = n-1; i > 0; i--) {
			packets.add(this.packets.get(i));
			
		}
		return packets;
				
	}
	
	public synchronized void write(Packet packet){
		
		this.packets.add(packet);
		this.notifyAll();
	}

	public Vector<Packet> getPackets() {
		return packets;
	}

	public void setPackets(Vector<Packet> packets) {
		this.packets = packets;
	}
	
	
	
	
}