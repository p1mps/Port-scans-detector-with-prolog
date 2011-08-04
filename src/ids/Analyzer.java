package ids;

import java.io.FileInputStream;
import java.util.Vector;
import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;
import alice.tuprolog.*;
import alice.tuprolog.Long;

public class Analyzer extends Thread{ 
	
	private Prolog engine;
	private Vector<TCPPacket> packets = new Vector<TCPPacket>();
	
	Analyzer(Prolog e) {this.engine = e;}
	
	public synchronized void retractPackets() {
		
		for (int i = 0; i < packets.size(); i++) {
			Term retractPacket = createPacket(packets.get(i));
			
			Term retract_query = new Struct("retract",retractPacket );
			System.out.println(retract_query);
			try{
		    	SolveInfo solve = engine.solve(retract_query);
		    	Term solution = solve.getSolution();
		    	System.out.println(solution);
		    }
		    catch(Exception e){}
			
			
		}
		
		
	}
	
	public Term createPacket(TCPPacket tcp_packet){
		
		Term t1 = new Int(tcp_packet.src_port);
	    Term t2 = new Int(tcp_packet.dst_port);
	    Term t3 = null;
	    Long t7 = null;
	    if (tcp_packet.syn)
	    	t3 = new Struct("syn");
	    
	    if(tcp_packet.rst){
	    	t3 = new Struct("rst");
	    
	    }
	    Term t4 = new Struct(tcp_packet.src_ip.toString());
		
	    Term t5 = new Struct(tcp_packet.dst_ip.toString());
	    
		Long t6 = new Long(tcp_packet.sequence);
  
	    
	    if(tcp_packet.ack){
	    	t7 = new Long(tcp_packet.ack_num);
	    }
	      
	    else
	    	t7 = new Long(0);
	    
	    Term[] arg_t;
	    
	    if (t3 != null){
	    	Term[] arg_temp = { t1,t2,t3,t4,t5,t6,t7 };
		    arg_t = arg_temp;
	    }
	    else{
		   	Term[] arg_temp = { t1,t2,t4,t5,t6,t7 };
		    arg_t = arg_temp;
	    }
	    
    	Term pair = new Struct( "pacchetto", arg_t );
    	return pair;
		
	}
	
	
	
	public synchronized void assertPacket(Packet p){
		
		if(p instanceof TCPPacket){
			
			TCPPacket tcp_packet = (TCPPacket)p;
			packets.add(tcp_packet);

			Term packet = createPacket(tcp_packet);

		    Term assert_query = new Struct("assert",packet );
	
		    try{
		    	SolveInfo solve = engine.solve(assert_query);
		    	Term solution = solve.getSolution();
		    	System.out.println(solution);
		    	
		    	
	    	}
	    	catch(Exception e){
	    		e.printStackTrace();
	    		
	    	}
	    	
		}
	}
	
	/* la stringa indica porta_chiusa o connessione_tcp */
	public String createStringTcpScan(Integer n,String s){
		
		
		String t1 = "tcp_scan(X,Y):- ";
		String t2 = "";
		String n1 = "";
		String n2 = "";
		
		for (int i = 1; i < n; i+=2) {
			
			n1 = "A"+(i);
			n2 = "A"+(i+1);
		
			if (i%2==1){
			  t2 += s + "(X,Y,"+n1+","+n2+"),";
			  t2 += n1 + "\\=" + n2 + ",";
			  
			  
			}
			
			
			
		}
		
		for(int i = 2; i < n; i+=2){
			
			for(int j = i; j < n; j+=2){
			n1 = "A"+(i);
			n2 = "A"+(j+2);
			
			t2 += n1 + "\\=" + n2;
			Integer i_integer = new Integer(j);
			
			if(i_integer.equals(new Integer(i)) && i!=2)
				  t2 += ".";
			  else
				  t2+=",";
			
			}
			
		}
		
		
		t1 += t2;
		
		return t1;

		
	}
	
	
	
	public void createRuleTcpScan(int n){
		
		try {
		
			String generated_rule = createStringTcpScan(n,"porta_chiusa");
			String generated_rule2 = createStringTcpScan(n,"connessione_tcp");
			Theory rule = new Theory(generated_rule);
			Theory rule2 = new Theory(generated_rule2);
			engine.addTheory(rule);
			engine.addTheory(rule2);
		
			
		} catch (InvalidTheoryException e) {
		}
		
		
		
		
		
	}
	
	
	

	/* legge da file kb.pl e crea stringa e aggiunge la regola con n premesse */
	
	public void initializeKB(String file,int n){
		 	
		
		try { 
			Theory kb = new Theory(new FileInputStream(file));
			engine.setTheory(kb);
			createRuleTcpScan(n);
		}
		catch (Exception e) {
			e.printStackTrace();

		}

		
		
		
	}
	
	
	public boolean query(){
		
		Term args2[] = { 
			new Var("X"),
			new Var("Y"),
		};
		
		Term query = new Struct("tcp_scan",	args2);
			
	    try {
	    	
	       	SolveInfo solve = engine.solve(query);
	       	Term solution = solve.getSolution();
	       	System.out.println(solution);
	       	return true;
	    }
	    catch(Exception e){
	       
	    	return false;
	        	
	    }
					
	}


}
