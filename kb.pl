/* pacchetti:

   CLIENT: syn, seq = x
   SERVER: syn, seq = y,ack= x + 1,
   CLIENT: seq = x + 1,ack = y + 1
   se porta chiusa
   CLIENT: rst,seq = x + 1,ack = y + 1
   
*/

/* regola per connessione tcp */
connessione_tcp(SOURCE,DESTINATION,SP,DP):-
pacchetto(SP,DP,syn,SOURCE,DESTINATION,X,0)% syn, seq = x
,pacchetto(DP,SP,syn,DESTINATION,SOURCE,Y,Z)%seq = y,ack= x + 1,
,pacchetto(SP,DP,SOURCE,DESTINATION,Z,W)%seq = x + 1,ack = y + 1
,Z is X+1,W is Y+1.




/* regola per connessione connessione syn */
connessione_syn(SOURCE,DESTINATION,SP,DP):-
pacchetto(SP,DP,syn,SOURCE,DESTINATION,X,0)% syn, seq = x
,pacchetto(DP,SP,syn,DESTINATION,SOURCE,Y,Z)%seq = y,ack= x + 1,
,Z is X+1.


/* regola per riconoscere se la porta e' chiusa */
porta_chiusa(SOURCE,DESTINATION,SP,DP):-
pacchetto(SP,DP,syn,SOURCE,DESTINATION,X,0)% syn, seq = x
,pacchetto(DP,SP,rst,DESTINATION,SOURCE,0,Z)%seq = x + 1,ack = y + 1
,Z is X+1.
	

