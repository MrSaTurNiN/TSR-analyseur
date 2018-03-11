#include "transport.h"
/** Jean-Philippe ABEGG, M1 CMI ISR **/
/**
 *	fonction d'analyse de l'entete udp
 *  const u_char* packet : adresse du premier octet de l'entete
 *	int* portSrc
 *	int* portDest
 *	int verbose
 */
int udp(const u_char* packet,int* portSrc,int* portDest, int verbose){
	struct udphdr* entete = (struct udphdr*) packet;
	*portSrc = ntohs(entete->source);
	*portDest = ntohs(entete->dest);
	output_header("UDP",verbose);
	switch(verbose){
		case VERBOSE_FAIBLE:
			fprintf(stdout, "%d -> %d ",*portSrc,*portDest);
			break;
		case VERBOSE_MOYEN:
			fprintf(stdout, "%d -> %d \n",*portSrc,*portDest);
			break;
		case VERBOSE_COMPLET:
			fprintf(stdout, "Port source %d\n", *portSrc);
			fprintf(stdout, "\tPort dest %d\n",*portDest);
			fprintf(stdout, "\tLen %d\n", ntohs(entete->len));
			fprintf(stdout, "\tChecksum %d\n", ntohs(entete->check));
			break;
		default:
			break;
	}
	return 8;
}
/**
 *	fonction d'analyse de l'entete tcp
 *  const u_char* packet : adresse du premier octet de l'entete
 * 	int size_ip: taille des données dans le paquet IP (hors header IP)
 *	int* portSrc: port source
 *	int* portDest: port destination
 *	int verbose
 */
int tcp(const u_char* packet,int* portSrc,int* portDest,int size_ip,int verbose){
	struct tcphdr* entete = (struct tcphdr*) packet;
	int size = entete->doff*4;
	*portSrc = ntohs(entete->source);
	*portDest = ntohs(entete->dest);
	output_header("TCP",verbose);
	switch(verbose){
		case VERBOSE_FAIBLE:
			//output verbose_faible: [TCP] port_src -> port_dest
			fprintf(stdout, "%d -> %d ",*portSrc,*portDest);
			if(size_ip - size == 0){
				flag_tcp(entete);
				fprintf(stdout, " | Seq %d, ", ntohs(entete->seq));
				fprintf(stdout, "Ack %d, ", ntohs(entete->ack_seq));
				fprintf(stdout, "Window %d", ntohs(entete->window));
			}
			break;
		case VERBOSE_MOYEN:
			//output verbose_moyen: TCP: port_src -> port_dest flag: flag_du_paquet
			fprintf(stdout, "%d -> %d ",*portSrc,*portDest);
			fprintf(stdout, " flag: ");
			flag_tcp(entete);
			if(size_ip - size != 0){
				fprintf(stdout, "\n");
			}
			break;
		case VERBOSE_COMPLET:
			fprintf(stdout, "Port source %d\n", *portSrc);
			fprintf(stdout, "\tPort dest %d\n", *portDest);
			fprintf(stdout, "\tSeq number %d\n", ntohs(entete->seq));
			fprintf(stdout, "\tAck number %d\n", ntohs(entete->ack_seq));
			fprintf(stdout, "\tData offset %d octets\n",size);
			fprintf(stdout, "\tFlag TCP:");
			flag_tcp(entete);
			fprintf(stdout, "\n\t");
			fprintf(stdout, "Window %d\n\t", ntohs(entete->window));
			if(size > 20){
				option_tcp(packet+20,size-20);
			}
			if(size_ip - size != 0){
				fprintf(stdout, "\n");
			}
			break;
		default:
			break;
	}
	return size;
}


//analyse les flag du paquet tcp
//les flags sont affiché sur la meme ligne
void flag_tcp(struct tcphdr* entete){
	if(entete->fin == 1){
		fprintf(stdout, "fin ");
	}
	if(entete->syn == 1){
		fprintf(stdout, "syn ");
	}
	if(entete->ack == 1){
		fprintf(stdout, "ack ");
	}
	if(entete->psh == 1){
		fprintf(stdout, "psh ");
	}
	if(entete->rst == 1){
		fprintf(stdout, "rst ");
	}
	if(entete->urg == 1){
		fprintf(stdout, "urg ");
	}
}

/**
 *	traduction du champs option de TCP, à utilisé si verbose = VERBOSE_COMPLET
 *	packet: un pointeur vers le premier char des options
 *	size: taille des options
 */
void option_tcp(const u_char* packet,int size){
	unsigned char t;
	unsigned char l;
	int i;
	fprintf(stdout, "Option (format hexa) : \n");
	while(size > 0){
		t = packet[0];
		if(t == 0)break;//fin des options, il reste que du padding
		fprintf(stdout, "\t\tT: %02hhX ",t);
		tcp_translate_option(t);
		if(t == 01){
			packet++;
			size--;
		}else{
			l = packet[1];
			fprintf(stdout, "L: %02hhX ",l);
			if(l>0)fprintf(stdout, "V: ");
			for(i = 0; i < l; i++){
				fprintf(stdout, "%02hhX ", packet[2+i]);
			}
			size-=l;
			packet+=l;
		}
		fprintf(stdout, "\n");
	}
}
/**
 *	traduit le T du TLV, d'un int vers une chaine de caractères
 */
void tcp_translate_option(int option){
	switch(option){
		case 1:
			fprintf(stdout, "(NOP) ");
			break;
		case 2:
			fprintf(stdout, "(MSS) " );
			break;
		case 4:
			fprintf(stdout, "(SACK permitted) " );
			break;
		case 5:
			fprintf(stdout, "(SACK) " );
			break;
		case 8:
			fprintf(stdout, "(Timestamp) " );
			break;
		default:
			fprintf(stdout, "(Unknow) " );
			break;
	}
}