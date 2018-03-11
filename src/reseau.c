#include "reseau.h"
/** Jean-Philippe ABEGG, M1 CMI ISR **/



/**
 *	Cette fonction va vérifier la version de IP et appeler la fonction d'analyse adapté à la version
 *	Note: IPv6 est actuellement non supporté
 *	return: taille de l'header IP si la version est supporté par le programme, -1 sinon	
 */
int ip(const u_char * packet,int* protocol,int* size,int verbose){
	//TEST POUR IPv4 ou IPv6
	int version = packet[0];
	version = version >> 4;
	if(version == 4){
		return ipv4(packet,protocol,size,verbose);
	}else if(version == 6){
		//IPv6 est actuellement non supporté
		fprintf(stdout, "IP: IPv6 ");
		if(verbose == VERBOSE_COMPLET){
			fprintf(stdout, "\n");
		}
		//call ici la fonction d'analyse IPv6
	}else{
		//ERREUR
	}
	return -1;
}


/**
 * fonction d'analyse de l'header IPv4
 * return: taille de l'header
 */
int ipv4(const u_char * packet,int* protocol,int* size,int verbose){
	struct ip* entete = (struct ip*)packet;
	struct in_addr source = entete->ip_src;
	struct in_addr dest = entete->ip_dst;
	*size = ntohs(entete->ip_len);
	*protocol = entete->ip_p;
	output_header("IP",verbose);
	switch(verbose){
		//verbose faible ou moyen: IP: ip_src -> ip_dst
		case VERBOSE_FAIBLE:
			fprintf(stdout, "%s ",inet_ntoa(source));
			fprintf(stdout, "-> %s ",inet_ntoa(dest));
			break;
		case VERBOSE_MOYEN:
			fprintf(stdout, "%s ",inet_ntoa(source));
			fprintf(stdout, "-> %s\n",inet_ntoa(dest));
			break;
		case VERBOSE_COMPLET:
			fprintf(stdout, "Header length %d\n",entete->ip_hl);
			fprintf(stdout, "\tVersion %d\n",entete->ip_v);
			fprintf(stdout, "\tType of service %d\n",entete->ip_tos);
			fprintf(stdout, "\tLen %d\n", *size);
			fprintf(stdout, "\tsource %s\n",inet_ntoa(source));
			fprintf(stdout, "\tdest %s\n",inet_ntoa(dest));
			fprintf(stdout, "\tID %d\n", ntohs(entete->ip_id));
			fprintf(stdout, "\tOffset %d\n", entete->ip_off);
			fprintf(stdout, "\tTTL %d\n", entete->ip_ttl);
			fprintf(stdout, "\tProtocol ");
			if(entete->ip_p == CODE_TCP){
				fprintf(stdout, "TCP (%d)\n",CODE_TCP);
			}else if(entete->ip_p == CODE_UDP){
				fprintf(stdout, "UDP (%d)\n",CODE_UDP);
			}else{
				fprintf(stdout, "??  (%d)\n", entete->ip_p);
			}
			fprintf(stdout, "\tChecksum %d\n",entete->ip_sum);
			break;
		default:
			break;
	}
	return entete->ip_hl*4;//taille de l'en-tete en octets
}


/**
 *	ARP, ne supporte que l'IPv4 et Ethernet
 */
void arp(const u_char* packet,int verbose){
	struct my_arp_header* header = (struct my_arp_header*)packet;
	output_header("ARP",verbose);
	if(verbose == VERBOSE_COMPLET){
		fprintf(stdout,"Hardware type: ");
		if(ntohs(header->ar_hdr) == ARP_ETHERNET){
			fprintf(stdout, "Ethernet (%d)\n", ntohs(header->ar_hdr));
		}else{
			fprintf(stdout, "? (%d)\n", ntohs(header->ar_hdr));
		}
		fprintf(stdout,"\tProtocol type: ");
		if(ntohs(header->ar_pro) == ARP_IP){
			fprintf(stdout, "IP (%d)\n",ntohs(header->ar_pro));
		}else{
			fprintf(stdout, "? (%d)\n",ntohs(header->ar_pro));
		}
		fprintf(stdout,"\tHardware Address Length: %d\n",header->ar_hln);
		fprintf(stdout,"\tProtocol Address Length: %d\n",header->ar_pln);
		fprintf(stdout,"\tOperation: %d\n",ntohs(header->ar_op));
		fprintf(stdout,"\tSource Mac: %s\n",ether_ntoa(&header->ar_sha));
		fprintf(stdout,"\tSource IP: %s\n",inet_ntoa(header->ar_sip));
		fprintf(stdout,"\tTarget Mac: %s\n",ether_ntoa(&header->ar_tha));
		fprintf(stdout,"\tTarget IP: %s\n",inet_ntoa(header->ar_tip));
	}else {
		if(ntohs(header->ar_op) == REQUEST_ARP){
			fprintf(stdout, " request: Who has %s ? ",inet_ntoa(header->ar_tip) );
			fprintf(stdout,"Tell %s",inet_ntoa(header->ar_sip));
		}else if(ntohs(header->ar_op) == ANSWER_ARP){
			fprintf(stdout, " answer: %s is at ",inet_ntoa(header->ar_sip) );
			fprintf(stdout,"%s",ether_ntoa(&header->ar_sha));
		}
	}
}

