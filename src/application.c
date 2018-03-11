#include "application.h"
/** Jean-Philippe ABEGG, M1 CMI ISR **/
/**
 * ensemble des fonctions pour analyser les informations de la couche application
 */


/**
 * analyse de SMTP
 * args:
 * 		packet: pointeur vers le octet des champs SMTP
 *		size: taille des données protocolaires
 * output:
 *		si verbose = VERBOSE_COMPLET -> intégralité des données applicatives
 *		sinon: première ligne de donnée
 */
void smtp(const u_char* packet,int size,int verbose){
	int i = 0;
	int print_return;
	if(size<=0)return;
	output_header("SMTP",verbose);
	if(verbose == VERBOSE_COMPLET){
		for (i = 0; i < size; i++){
			print_return = print_char(packet[i]);
			if(print_return == '\n'){
				fprintf(stdout, "\t");
			}
		}	
	}else{
		for (i = 0; i < size && packet[i] != '\n'; i++){
			print_char(packet[i]);
		}		
	}
}

/**
 * analyse de POP
 * args:
 * 		packet: pointeur vers le octet des champs POP
 *		size: taille des données protocolaires
 * output:
 *		si verbose = VERBOSE_COMPLET -> intégralité des données applicatives
 *		sinon: première ligne de donnée
 */
void pop(const u_char* packet,int size,int verbose){
	int i;
	if(size<=0)return;
	output_header("POP",verbose);
	if(verbose == VERBOSE_COMPLET){
		for (i = 0; i < size; i++){
			print_char(packet[i]);
		}
	}else{

		for (i = 0; i < size && packet[i] != '\n'; i++){
			print_char(packet[i]);
		}
		fprintf(stdout, "\n");
	}
}

/**
 * analyse de HTTP
 * args:
 * 		packet: pointeur vers le octet des champs HTTP
 *		size: taille des données protocolaires
 * output:
 *		si verbose = VERBOSE_COMPLET -> intégralité des données applicatives
 *		sinon: première ligne de donnée
 */
void http(const u_char* packet,int size,int verbose){
	int i;
	if(size<=0)return;
	output_header("HTTP",verbose);
	if(verbose == VERBOSE_COMPLET){
		for (i = 0; i < size; i++){
			if(print_char(packet[i]) == '\n'){
				fprintf(stdout, "\t");
			}
		}
	}else{
		for (i = 0; i < size && packet[i] != '\n' ; i++){
			print_char(packet[i]);
		}
	}
}

/**
 * analyse de HTTPS
 * args:
 * 		packet: pointeur vers le octet des champs HTTPS
 *		size: taille des données protocolaires
 * output:
 *		si verbose = VERBOSE_COMPLET -> intégralité des données applicatives chiffrées
 *		sinon: 10 premier octets
 */
void https(const u_char* packet,int size,int verbose){
	int i;
	if(size<=0)return;
	output_header("HTTPS",verbose);
	if(verbose == VERBOSE_COMPLET){
		for (i = 0; i < size; i++){
			if(print_char(packet[i]) == '\n'){
				fprintf(stdout, "\t");
			}
		}
	}else{
		for (i = 0; i < size && i < 10; i++){
			print_char(packet[i]);
		}
	}
}

/**
 * analyse de IMAP
 * args:
 * 		packet: pointeur vers le octet des champs IMAP
 *		size: taille des données protocolaires
 * output:
 *		si verbose = VERBOSE_COMPLET -> intégralité des données applicatives
 *		sinon: première ligne de donnée
 */
void imap(const u_char* packet,int size,int verbose){
	int i;
	if(size<=0)return;
	output_header("IMAP",verbose);
	if(verbose == VERBOSE_COMPLET){
		//on affiche l'intégralité du contenu	
		fprintf(stdout, ":\t");
		for (i = 0; i < size; i++){
			if(print_char(packet[i]) == '\n'){
				fprintf(stdout, "\t");
			}
		}
	}else{
		//On affiche la première ligne 
		if(verbose == VERBOSE_FAIBLE){
			if(packet[0] == '*'){
				fprintf(stdout, "Response: ");
			}else{
				fprintf(stdout, "Request: ");
			}
		}
		for (i = 0; i < size && packet[i] != '\n'; i++){
			print_char(packet[i]);
		}
	}
}


/**
 * analyse de Telnet
 * args:
 * 		packet: pointeur vers le octet des champs Telnet
 *		size: taille des données protocolaires
 * output:
 *		si verbose = VERBOSE_COMPLET -> intégralité des données applicatives
 *		sinon: DATA ou un char
 */
void telnet(const u_char* packet,int size,int verbose){
	int i;
	if(size<=0)return;
	output_header("Telnet",verbose);
	if(verbose == VERBOSE_FAIBLE || verbose == VERBOSE_MOYEN){
		if(packet[0] == IAC){
			fprintf(stdout, "DATA\n");
			return;
		}else{
			for (i = 0; i < size && packet[i] != '\n'; i++){
				print_char(packet[i]);
			}
			fprintf(stdout, "\n");
		}
	}
	if(verbose == VERBOSE_COMPLET){
		if(packet[0] == IAC){
			//Affichage des négociations
			telnet_negociation(packet,size);
		}else{
			for (i = 0; i < size; i++){
				print_char(packet[i]);
			}
		}
	}
}

/**
 *	traduction de la négociation des options Telnet
 *	il faut utiliser cette fonction quand verbose = VERBOSE_COMPLET
 * 	args:
 * 		packet: pointeur vers le octet des champs Telnet
 *		size: taille des données protocolaires
 */
void telnet_negociation(const u_char* packet,int size){
	const unsigned char* byte = (const unsigned char*)packet;
	const unsigned char* before;
	int read = 0;
	fprintf(stdout, "\n");
	while(*byte == IAC && read < size){
		byte++;
		read++;
		switch(*byte){
			case DO:
				fprintf(stdout, "\t-do ");
				byte++;
				read++;
				telnet_option(byte);
				break;
			case DONT:
				fprintf(stdout, "\t-dont ");
				byte++;
				read++;
				telnet_option(byte);
				break;
			case WILL:
				fprintf(stdout, "\t-will ");
				byte++;
				read++;
				telnet_option(byte);
				break;
			case WONT:
				fprintf(stdout, "\t-wont ");
				byte++;
				read++;
				telnet_option(byte);		
				break;
			case EC:
				fprintf(stdout, "\t-erase character ");
				break;
			case EL:
				fprintf(stdout, "\t-erase line");
				break;
			case GA:
				fprintf(stdout, "\t-go ahead");
				break;
			case SB:
				fprintf(stdout, "\t-sub option, ");
				byte++;
				read++;
				telnet_option(byte);
				fprintf(stdout, " value :");
				before = byte-1;
				while(read < size && *byte != SUB_OPTION_END_BYTE_TWO && *before != SUB_OPTION_END_BYTE_TWO){
					fprintf(stdout, "%02hhX ",*byte);
					before = byte;
					byte++;
					read++;
				}
				fprintf(stdout, "%02hhX ",*byte);
				break;
			case AO:
				fprintf(stdout, "\t-abort output ");
				break;
			case NOP:
				fprintf(stdout, "\t-NOP ");
				break;
			case DM:
				fprintf(stdout, "\t-data mark");
				break;
			case IP:
				fprintf(stdout, "\t-interrupt process");
				break;
			case AYT:
				fprintf(stdout, "\t-are you there");
				break;
			default:
				fprintf(stdout, "\t-unknow control character");
				break;
		}
		byte++;
		read++;
		fprintf(stdout, "\n");
	}
}





/**
 *	Traduction: valeur du byte en nom de l'option
 * 	voir: telnet_negociation
 */
int telnet_option(const unsigned char* byte){
	switch(*byte){
		case ECHO:
			fprintf(stdout, "echo ");
			break;
		case SUPPR_GO_AHEAD:
			fprintf(stdout, "suppr go ahead ");
			break;
		case TERMINAL_TYPE:
			fprintf(stdout, "terminal type");
			break;
		case WINDOW_SIZE:
			fprintf(stdout, "window size ");
			break;
		case TERM_SPEED:
			fprintf(stdout, "term speed ");
			break;
		case LINE_MODE:
			fprintf(stdout, "line mode ");
			break;
		case ENV_VAR:
			fprintf(stdout, "env var ");
			break;
		case NEW_ENV_VAR:
			fprintf(stdout, "new env var ");
			break;
		default:
			fprintf(stdout, "unknow option (%d)",*byte);
			break;
	}
	return *byte;
}

/**
 *	traduction des champs lié à DHCP ou BOOTP
 *	packet: pointeur vers le octet des champs DNS/BOOTP
 */
void dhcp_bootp(const u_char* packet,int verbose){
	struct bootp* entete = (struct bootp*)packet;
	unsigned char* vendor = entete->bp_vend;
	bool is_dhcp = true;
	//test sur le magic cookie
	//permet de différencier DHCP et BOOTP
	if(vendor[0] == MAGIC_COOKIE_BIT_1 && vendor[1] == MAGIC_COOKIE_BIT_2 && vendor[2] == MAGIC_COOKIE_BIT_3 && vendor[3] == MAGIC_COOKIE_BIT_4 ){
		output_header("DHCP",verbose);
	}else{
		output_header("BOOTP",verbose);
		is_dhcp = false;
		return;
	}
	if(verbose == VERBOSE_COMPLET){
		fprintf(stdout, "operation: %d\n",entete->bp_op);
		fprintf(stdout, "\thtype: %d\n",entete->bp_htype);
		fprintf(stdout, "\thlen: %d\n",entete->bp_hlen);
		fprintf(stdout, "\thops: %d\n",entete->bp_hops);
		fprintf(stdout, "\txid: %d\n",entete->bp_xid);
		fprintf(stdout, "\tsecs: %d\n",entete->bp_secs);
		fprintf(stdout, "\tflags: %d\n",entete->bp_flags);
		fprintf(stdout,"\tciaddr: %s\n",inet_ntoa(entete->bp_ciaddr));
		fprintf(stdout,"\tyiaddr: %s\n",inet_ntoa(entete->bp_yiaddr));
		fprintf(stdout,"\tsiaddr: %s\n",inet_ntoa(entete->bp_siaddr));
		fprintf(stdout,"\tgiaddr: %s\n",inet_ntoa(entete->bp_giaddr));
		fprintf(stdout, "\tchaddr: %s\n",entete->bp_chaddr);
		fprintf(stdout, "\tsname: %s\n",entete->bp_sname);
		fprintf(stdout, "\tfile: %s\n",entete->bp_file);
		//traduction du vendor
		fprintf(stdout, "\tvendor:\n");
		if(is_dhcp){
			fprintf(stdout, "\t\tmagic cookie\n");
			vendor = vendor + 4;
			dhcp_vendor(vendor,BOOTP_VENDSIZE-4);
		}else{
			dhcp_vendor(vendor,BOOTP_VENDSIZE);
		}
	}else{
		if(is_dhcp){
			vendor = vendor + 4;//magic cookie
			vendor = vendor + 1;//T
			vendor = vendor + 1;//L
			dhcp_translate_operation(vendor[0]);
		}
		fprintf(stdout, "transaction ID: %d\n", entete->bp_xid);
	}
}

//traduit le contenu du vendor (sans le magic cookie)
void dhcp_vendor(unsigned char* packet,int size){
	unsigned char t;
	unsigned char l;
	int i;
	while(size > 0){
		t = packet[0];
		packet++;
		size--;
		if(t == 255){
			fprintf(stdout, "\t\tEnd (255)\n");
			break;//fin des options, il reste que du padding
		}
		fprintf(stdout, "\t\tT:  ");
		dhcp_translate_option(t);
		l = packet[0];
		packet++;
		size--;
		fprintf(stdout, "L: %d ",l);
		if(l>0)fprintf(stdout, "V: ");
		if(t != 53){
			for(i = 0; i < l; i++){
				fprintf(stdout, "%d ", packet[i]);		
			}
		}else{
			dhcp_translate_operation(packet[0]);
		}
		
		packet+=l;
		size-=l;
		fprintf(stdout, "\n");
	}
}

void dhcp_translate_option(int option){
	switch(option){
		case 53:
			fprintf(stdout, "DHCP message type ");
			break;
		case 1:
			fprintf(stdout, "submask net ");
			break;
		default:
			fprintf(stdout, "%d ",option);
			break;
	}
}

void dhcp_translate_operation(int operation){
	switch(operation){
		case DHCPDISCOVER:
		fprintf(stdout, "DISCOVER ");
		break;
		case DHCPOFFER:
		fprintf(stdout, "OFFER ");
		break;
		case DHCPREQUEST:
		fprintf(stdout, "REQUEST ");
		break;
		case DHCPDECLINE:
		fprintf(stdout, "DECLINE ");
		break;
		case DHCPACK:
		fprintf(stdout, "ACK ");
		break;
		case DHCPNAK:
		fprintf(stdout, "NACK ");
		break;
		case DHCPRELEASE:
		fprintf(stdout, "RELEASE ");
		break;
		default:
		fprintf(stdout, "unknow operation ");
		break;
	}
}


void ftp_data(const u_char* packet,int size,int verbose){
	int i = 0;
	int print_return;
	if(size<=0)return;
	output_header("FTP",verbose);
	if(verbose == VERBOSE_COMPLET){
		for (i = 0; i < size; i++){
			print_return = print_char(packet[i]);
			if(print_return == '\n'){
				fprintf(stdout, "\t");
			}
		}	
	}else{
		fprintf(stdout, "DATA");
	}
}

void ftp_control(const u_char* packet,int size,int port_src,int verbose){
	int i = 0;
	int print_return;
	if(size<=0)return;//si il n'y aucun contenu, on affiche rien
	output_header("FTP",verbose);
	if(verbose == VERBOSE_COMPLET){
		//on affiche l'intégralité du contenu
		for (i = 0; i < size; i++){
			print_return = print_char(packet[i]);
			if(print_return == '\n'){
				fprintf(stdout, "\t");
			}
		}	
	}else{
		//test pour savoir si il s'agit d'une réponse du serveur ou une réquete du client
		if(port_src == PORT_FTP_CONTROL_SERVER)fprintf(stdout, "Response : ");
		else fprintf(stdout, "Request : ");
		for (i = 0; i < size && packet[i] != '\n'; i++){
			print_char(packet[i]);
		}		
	}
}

/**
 *	traduction des champs de DNS
 *	packet: pointeur vers le premier char de DNS
 *	size: taille total du champs dns
 */
void dns(const u_char* packet,int size,int verbose){
	struct dns_header* header = (struct dns_header*)packet;
	int i;
	output_header("DNS",verbose);
	if(verbose == VERBOSE_COMPLET){
		fprintf(stdout, "transaction ID: %d\n",ntohs(header->id));
		fprintf(stdout, "\trd: %d\n",ntohs(header->rd));
		fprintf(stdout, "\ttc: %d\n",ntohs(header->tc));
		fprintf(stdout, "\taa: %d\n",ntohs(header->aa));
		fprintf(stdout, "\topcode: %d\n",ntohs(header->opcode));
		fprintf(stdout, "\tqr: %d\n",ntohs(header->qr));
		fprintf(stdout, "\trcode: %d\n",ntohs(header->rcode));
		fprintf(stdout, "\tcd: %d\n",ntohs(header->cd));
		fprintf(stdout, "\tad: %d\n",ntohs(header->ad));
		fprintf(stdout, "\tz: %d\n",ntohs(header->z));
		fprintf(stdout, "\tra: %d\n",ntohs(header->ra));
		fprintf(stdout, "\trcode: %d\n",ntohs(header->cd));
		fprintf(stdout, "\tquestion: %d\n",ntohs(header->q_count));
		fprintf(stdout, "\tanswer rr: %d\n",ntohs(header->ans_count));
		fprintf(stdout, "\tauthority rr: %d\n",ntohs(header->auth_count));
		fprintf(stdout, "\tadditional rr: %d\n",ntohs(header->add_count));
		fprintf(stdout, "\tquery:\n\t\t");
		for (i = sizeof(struct dns_header); i < size; i++){
			if(print_char(packet[i]) == '\n'){
				fprintf(stdout, "\t\t");
			}
		}
		//dns_write_answer(packet+sizeof(struct dns_header),0);
	}else{
		fprintf(stdout, "transaction ID: %d, query: ",ntohs(header->id));
		for (i = 0; i < size && packet[i] != '\n'; i++){
			print_char(packet[i]);
		}	
	}
	//TTL 4 octets
	//data lenghth 4 peut -etre IP
	//c = pointeur
}

/**
 *	Affiche une répose dans query
 *		-> le nom, type, classe
 */
//ne fonctionne pas
int dns_write_answer(const unsigned char* packet,int delta){
	const unsigned char* query = packet + delta;
	//name -> string ou pointeur
	while(*query != 0){
		if(*query == 0xC0 || 0xC1){
			if(*query == 0xC1){
				return dns_write_answer(packet,255 + query[1]);
			}else{
				return dns_write_answer(packet,query[1]);
			}
		}else{
			print_char((*query));
			query++;
		}
	}
	return 0;
}

/*
 *	Si c est imprimable: affiche c sur stdout et retourne c
 *	Si c est non imprimable: affiche '.' sur stdout et retourne une valeur supérieur à max(unsigned char)
 */
int print_char(char c){
	if(c == '\n'){
		fprintf(stdout, "\n");
	}
	else if(isprint(c)){
		fprintf(stdout, "%c",c);
	}else{
		fprintf(stdout, ".");
		return NOT_PRINTABLE;
	}
	return c;
}
