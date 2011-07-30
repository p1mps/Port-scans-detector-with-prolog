package ids;

import java.io.FileInputStream;
import java.util.Vector;
import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;
import alice.tuprolog.*;
import alice.tuprolog.Long;

public class Analyzer extends Thread{ 
	
	private Blackboard blackboard;
	private Prolog engine;
	private Vector<TCPPacket> packets = new Vector<TCPPacket>();
	/* numero pacchetti da leggere */
	//private int n;
	/*lista ip diversi da ip host per cui fare inferenza*/
	
	
	
	//Analyzer(int n) { this.n = n; }
	
	Analyzer(Prolog e) {this.engine = e;}
	
	public synchronized void retractPackets() {
		
		for (int i = 0; i < packets.size(); i++) {
			Term retractPacket = createPacket(packets.get(i));
			
			Term retract_query = new Struct("retract",retractPacket );
			System.out.println("Rectract packets " + retract_query);
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
	    //Long t6 = new Long(l_t6); already defined on 2p
	    
	    
	    if(tcp_packet.ack){
	    	t7 = new Long(tcp_packet.ack_num);
	    	//t7 = new Integer(l);
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
			//System.out.println(tcp_packet);
			Term packet = createPacket(tcp_packet);
		    //System.out.println(packet);
		    Term assert_query = new Struct("assert",packet );
	
		    try{
		    	SolveInfo solve = engine.solve(assert_query);
		    	Term solution = solve.getSolution();
		    	System.out.println("assert " + solution);
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
		
		System.out.println(t1);
		
		return t1;
		
		
		/*
		String t1 = "tcp_scan(X,Y):- ";
		String t2 = "";
		String t3 = "";
		String n1 = "";
		String n2 = "";
		Integer n_less_1 = new Integer(n-1);
		for (int i=1; i < n;i++){
			  n1 = "A"+(i);
			  n2 = "A"+(i+1);
			  Integer i_integer = new Integer(i);
			  
			  //System.out.println(i_integer +","+i);
			  if (i%2==1)
			  t2 += "connessione_tcp(X,Y,"+n1+","+n2+"),";
			  
			  for (int j=i; j < n;j++){
				  n1 = "A"+(i);
				  n2 = "A"+(j+1);
				  
				  t3 += n1+"\\="+n2;

				  if(i_integer.equals(n_less_1)){
					  
					  t3 += ".";
				  }
				  else
					  t3 += ",";
				    
			  }
			  //System.out.println("t3 costruita " + t3);
		} 
		
		
		
		t1 += t2+t3;
		System.out.println("regola generata: " + t1 + "-");
		return t1;
		
		*/
		
	}
	
	
	
	public void createRuleTcpScan(int n){
		
		try {
			/*Theory rule = new Theory("tcp_scan(SOURCE,DESTINATION):-connessione_tcp(SOURCE,DESTINATION,A,B),connessione_tcp(SOURCE,DESTINATION,C,D),connessione_tcp(SOURCE,DESTINATION,E,F)," +
					"A \\== B,A \\== C,A \\== D,B \\== C,C \\== E, A \\== E,B \\== F.");
			*/
			String generated_rule = createStringTcpScan(n,"porta_chiusa");
			String generated_rule2 = createStringTcpScan(n,"connessione_tcp");
			System.out.println("generated rule " + generated_rule);
			System.out.println("generated rule2 " + generated_rule2);
			//System.out.println("rule " +rule);
			Theory rule = new Theory(generated_rule);
			Theory rule2 = new Theory(generated_rule2);
			engine.addTheory(rule);
			engine.addTheory(rule2);
			System.out.println("ok");
			
		} catch (InvalidTheoryException e) {
			// TODO Auto-generated catch block
			//e.printStackTrace();
		}
		
		
		
		
		
	}
	
	
	

	/* legge da file kb.pl e crea stringa e aggiunge la regola con n premesse */
	
	public void initializeKB(String file,int n){
		 	
		
		try { 
			Theory kb = new Theory(new FileInputStream(file));
			engine.setTheory(kb);
			createRuleTcpScan(n);
			//System.out.println(dynamic_rule.toString());
			
			
		}
		catch (Exception e) {
			e.printStackTrace();
	
			
		}
		finally {}
		
		
		
	}
	
	
	public void query(){
		System.out.println("eseguo query");
		Term args2[] = { 
				//new Atom("/192.168.0.5"),
				//new Atom("/192.168.0.4"),
				new Var("X"),
				new Var("Y"),
				//new Variable("W"),
				//new Variable("Z"),
			};
			Term query = 
				new Struct(
					//"porta_chiusa",
					"tcp_scan",
					//	"connessione_tcp",
					//	"main"
					args2 
					);
			
	    	try{
	    		System.out.println("query " + query);
	        	SolveInfo solve = engine.solve(query);
	        	Term solution = solve.getSolution();
	        	System.out.println("solution " + solution);
	        	System.exit(0);
	        	}
	        catch(Exception e){
	        	e.printStackTrace();
	        	
	        	
	        }
			
			
/*			if(query.hasSolution()){
				System.out.println(query.oneSolution());
				System.out.println("scanning rilevato!");
			    System.exit(1);
			}
			/*
			 while (query.hasMoreElements()){
			     Term bound_to_x = (Term)((Hashtable) query.nextElement()).get("X");
			     Term bound_to_y = (Term)((Hashtable) query.nextElement()).get("Y");
			     //Term bound_to_w = (Term)((Hashtable) query.nextElement()).get("W");
			     System.out.println("X="+bound_to_x);
			     System.out.println("Y="+bound_to_y);
			     //System.out.println("W="+bound_to_w);
			     //System.out.prine ids;

import java.awt.Toolkit;
import java.util.Timer;
import java.util.TimerTask;

public class RetractTimer {
	
	private Analyzer analyzer;
	
	private Toolkit toolkit;

	private Timer timer;
tln("Z="+bound_to_z);
			 }
			*/
			
	}

	/*
	public void run(){
		
		synchronized (blackboard) {
				
			
		System.out.println("mi hanno svegliato!");
		Vector<Packet> packets = this.blackboard.read(this.blackboard.getPackets().size());
			
		for (int i = 0; i < packets.size(); i++) {
			this.assertPacket(packets.get(i));
			
		}
		blackboard.notifyAll();
		}
		this.query();
		}
	*/	
	


	public Blackboard getBlackboard() {
		return blackboard;
	}


	public void setBlackboard(Blackboard blackboard) {
		this.blackboard = blackboard;
	}
}
