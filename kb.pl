/* KB DEFINITIVA */
/*gestire RST!*/

/* connessione tcp */
/* pacchetti:

   CLIENT: syn, seq = x
   SERVER: syn, seq = y,ack= x + 1,

   CLIENT: seq = x + 1,ack = y + 1
   se porta chiusa
   CLIENT: rst,seq = x + 1,ack = y + 1
   
*/


connessione_tcp(SOURCE,DESTINATION,SD,DP):-
	pacchetto(SD,DP,syn,SOURCE,DESTINATION,X,0)% syn, seq = x
	,pacchetto(DP,SD,syn,DESTINATION,SOURCE,Y,Z)%seq = y,ack= x + 1,
	,pacchetto(SD,DP,SOURCE,DESTINATION,Z,W)%seq = x + 1,ack = y + 1
	,Z is X+1,W is Y+1.




connessione_syn(SOURCE,DESTINATION,SD,DP):-
	pacchetto(SD,DP,syn,SOURCE,DESTINATION,X,0)% syn, seq = x
	,pacchetto(DP,SD,syn,DESTINATION,SOURCE,Y,Z)%seq = y,ack= x + 1,
	,Z is X+1.



porta_chiusa(SOURCE,DESTINATION,SD,DP):-
	pacchetto(SD,DP,syn,SOURCE,DESTINATION,X,0)% syn, seq = x
	,pacchetto(DP,SP,rst,DESTINATION,SOURCE,0,Z)%seq = x + 1,ack = y + 1
	,Z is X+1.
	

