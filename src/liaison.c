#include "liaison.h"
/** Jean-Philippe ABEGG, M1 CMI ISR **/
/**
 * analyse l'en-tete Ethernet
 * On affiche rien pour cette couche si verbose == VERBOSE_FAIBLE
 * return: taille de l'header ethernet
 */
int ethernet(const u_char * packet,int* protocol_reseau,int verbose){
	struct ether_header* header;
	struct ether_addr*  mac_src;
	struct ether_addr*  mac_dest;
	header = (struct ether_header*)packet;
	mac_dest = (struct ether_addr*) header->ether_dhost;
	mac_src = (struct ether_addr*) header->ether_shost;
	*protocol_reseau =  ntohs(header->ether_type);
	if(verbose == VERBOSE_COMPLET){
		fprintf(stdout, "Ethernet:\n");
		fprintf(stdout, "\t destination addr %s \n",ether_ntoa(mac_dest));
		fprintf(stdout, "\t source addr %s \n",ether_ntoa(mac_src));
		fprintf(stdout, "\t type ");
		//traduction du protocole réseau
		if(*protocol_reseau == ETHERTYPE_IP){
			fprintf(stdout, "IP");
		}else if(*protocol_reseau == ETHERTYPE_ARP){
			fprintf(stdout, "ARP");
		}
		else{
			fprintf(stdout, "?");
		}
		fprintf(stdout, "\n\n");
	}
	if(verbose == VERBOSE_MOYEN){
		//verbose moyen : Ethernet: dest: mac_dest, src: mac_src
		fprintf(stdout, "\tEthernet: dest: %s, ",ether_ntoa(mac_dest)); 
		fprintf(stdout, "src: %s\n",ether_ntoa(mac_src));
	}

	if(verbose == VERBOSE_FAIBLE && *protocol_reseau == ETHERTYPE_ARP){
		fprintf(stdout, "[Ethernet] %s -> ",ether_ntoa(mac_src));
		fprintf(stdout, "%s ",ether_ntoa(mac_dest));
		
	}

	return sizeof(struct ether_header);
}

