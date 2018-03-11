/** Jean-Philippe ABEGG, M1 CMI ISR **/
#include "capture.h"
/**
 * Analyseur de trame réseau
 *
 * Ce logiciel est capable d'analyser les trames dans un fichier ou 
 * directement sur une interface (si on a les droits root).
 * 
 * Protocoles supportés:
 *		-Ethernet
 *		-IP
 *		-ARP
 *		-UDP
 *		-TCP
 *		-BOOTP / DHCP
 *		-Telnet
 *		-POP
 *		-IMAP
 *		-HTTP(S)
 *		-SMTP
 *		-FTP
 *		-DNS
 * options:
 *		-v valeur 	: indiquer le format de sortie du programme
 *		-o name 	: indiquer un fichier à analyser
 *		-i interface: indiquer l'interface sur laquelle faire la capture
 *		-f filter 	: appliquer un filtre sur la capture
 */
int main(int argc, char **argv){
	char file_name [STRING_SIZE];
	char device_name [STRING_SIZE];
	char filter_query [STRING_SIZE];
	char erreur [PCAP_ERRBUF_SIZE];
	u_char args[1];//argument pour pcap_loop, le seul argument de cette fonction est la verbosité sur 1 octets
	//verbosité de la sortie du programme
	int verbose = VERBOSE_MOYEN;// valeur par défault
	int loop_return;
	char c;
	int lines_to_read = -1;
	bool flag_o = false;//fichier d'entré
	bool flag_i = false;//device pour la capture
	bool flag_f = false;//filtre
	bool flag_v = false;//verbosité
	pcap_t* capture;
	struct bpf_program fp;
	/* Analyser les options */
	 do{
		c = getopt(argc,argv,"n:v:o:i:f:");
		switch(c){
			case 'o':
				snprintf(file_name, STRING_SIZE, optarg);
				flag_o = true;
			break;
			case 'i':
				snprintf(device_name, STRING_SIZE, optarg);
				flag_i = true;
			break;
			case 'v':
				verbose = atoi(optarg);
				if(verbose != VERBOSE_COMPLET && verbose != VERBOSE_MOYEN && verbose != VERBOSE_FAIBLE){
					fprintf(stderr, "Error: -v value, value between 1 and 3. 1 = one line peer packet, 2 = one line peer header, 3 = full intels\n");
					exit(1);
				}
				flag_v = true;
			break;
			case 'f':
				flag_f = true;
				snprintf(filter_query, STRING_SIZE, optarg);
			break;
			case '?':
				fprintf(stderr, "Usage: %s [-i interface_name] [-o file_name] -v verbose [-f 'filter']\n",argv[0]);
				exit(1);
			break;
			default:
			break;
		}
	}while(c != -1);

	if(flag_v == false){
		fprintf(stderr, "usage: you have to use -v verbose \n");
	}
	if(flag_i && flag_o){
		fprintf(stderr, "usage: you can't do -o and -i during the same execution\n");
	}
	args[0] = (u_char)verbose;
	/* lancer la capture  */
	//ouverture de la trace 
	if(flag_o){
		capture = pcap_open_offline(file_name,erreur);
		if(capture == NULL){
			fprintf(stderr, "%s: %s\n",file_name,erreur);
			exit(1);
		}
	}else{
		lines_to_read = -1;
		capture = pcap_open_live(device_name,BUFSIZ,1, 1000,erreur);
		if(capture == NULL){
			fprintf(stderr, "%s: %s\n",device_name,erreur);
			exit(1);
		}
	}
	//mise en place du filtre 
	if(flag_f){
		if (pcap_compile(capture, &fp, filter_query, 0, 0) == -1) {
			fprintf(stderr, "ERROR: pcap_compile %s: %s\n", filter_query, pcap_geterr(capture));
			exit(1);
	 	}
	 	if (pcap_setfilter(capture, &fp) == -1) {
		 	fprintf(stderr, "ERROR: pcap_setfilter %s: %s\n", filter_query, pcap_geterr(capture));
		 	exit(1);
	 	}
	}
	loop_return = pcap_loop(capture,lines_to_read,got_packet,args);
	if(loop_return == -1){
		fprintf(stderr, "ERROR: pcap_loop\n");
		exit(1);
	}
	pcap_close(capture);
	return 0;
}



/** fonction de callback **/
void got_packet (u_char *args, const struct pcap_pkthdr 
*header, const u_char *packet){
	static unsigned long id_packet = 0;
	id_packet++;
	fprintf(stdout, "packet %ld: \n",id_packet);
	int verbose = args[0];
	unsigned int size = header->len;//nombre total d'octets dans le paquet
	int return_ip;//taille de l'header IPv4 ou -1 si IPv6
	int protocol_transport;
	int protocol_reseau;
	int port_src;//port source à la couche transport
	int port_dest;//port de destination à la couche transport
	int delta;//nombre d'octets lu dans le paquet
	int size_data;//nombre d'octets de donnée à la couche applicative
	//On analyse le paquet, un entete à la fois
	//Couche II
	delta = ethernet(packet,&protocol_reseau,verbose);
	//Couche III
	if(protocol_reseau == ETHERTYPE_IP){
		return_ip = ip(packet + delta,&protocol_transport,&size_data,verbose);
		//vérifier si le paquet utilise une version d'IP supportée par l'application
		if(return_ip != -1){
			delta +=return_ip;
			if(protocol_transport == CODE_UDP){
				//Couche IV == UDP
				delta = delta + udp(packet + delta,&port_src,&port_dest,verbose);
				size_data = size - delta;//octets restant à lire
				//traitement de la couche applicative pour UDP
				//DHCP
				if(port_src == DHCP_CLIENT_PORT || port_src == DHCP_SERVER_PORT || port_dest == DHCP_CLIENT_PORT || port_dest == DHCP_SERVER_PORT ){
					dhcp_bootp(packet + delta,verbose);
				}else if(port_src == DNS_PORT || port_dest == DNS_PORT){
					dns(packet + delta,size_data,verbose);
				}
			}else if(protocol_transport == CODE_TCP){
				//Couche IV == TCP
				delta = delta + tcp(packet + delta,&port_src,&port_dest,size - delta,verbose);
				size_data = size - delta;//octets restant à lire
				//traitement de la couche applicative pour TCP
				if(port_src == HTTP_PORT || port_dest == HTTP_PORT){
					http(packet + delta,size_data,verbose);
				}else if(port_dest == SMTP_PORT || port_src == SMTP_PORT){
					smtp(packet + delta,size_data,verbose);
				}else if(port_dest == IMAP_PORT || port_src == IMAP_PORT){
					imap(packet + delta,size_data,verbose);
				}else if(port_src == POP_PORT || port_src == POP_PORT){
					pop(packet + delta,size_data,verbose);
				}else if(port_dest == TELNET_PORT || port_src == TELNET_PORT){
					telnet(packet + delta,size_data,verbose);
				}else if(port_dest == FTP_CONTROL_PORT || port_src == FTP_CONTROL_PORT){
					ftp_control(packet + delta,size_data,port_src,verbose);
				}else if(port_dest == FTP_DATA_PORT || port_src == FTP_DATA_PORT){
					ftp_data(packet + delta,size_data,verbose);
				}else if(port_dest == HTTPS_PORT || port_src == HTTPS_PORT){
					https(packet + delta,size_data,verbose);
				}
			}
		}
	}else if(protocol_reseau == ETHERTYPE_ARP){
		arp(packet + delta,verbose);
	}
	fprintf(stdout, "\n\n");
	
}



/**
 * affiche le nom du protocol en fonction de verbose
 */
void output_header(char* protocol_name,int verbose){
	switch(verbose){
		case VERBOSE_FAIBLE:
		fprintf(stdout, "[");
		fprintf(stdout, "%s",protocol_name);
		fprintf(stdout, "] ");
		break;
		case VERBOSE_MOYEN:
		fprintf(stdout, "\t%s",protocol_name);
		fprintf(stdout, ": ");
		break;
		case VERBOSE_COMPLET:
		fprintf(stdout, "%s:",protocol_name);
		fprintf(stdout, "\n\t");
		break;
	}
}