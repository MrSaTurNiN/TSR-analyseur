#ifndef RESEAU_H
#define RESEAU_H
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include "capture.h"
#define CODE_TCP 6
#define CODE_UDP 17
#define REQUEST_ARP 1
#define ANSWER_ARP 2
#define ARP_ETHERNET 1
#define ARP_IP 2048


//impossible d'utiliser la structure présente dans les .h de net/ pour le protocole ARP
struct my_arp_header{
	unsigned short int ar_hdr;
	unsigned short int ar_pro;
	unsigned char ar_hln;
	unsigned char ar_pln;
	unsigned short int ar_op;
	struct ether_addr ar_sha;
	struct in_addr ar_sip;
	struct ether_addr ar_tha;
	struct in_addr ar_tip;
};

int ip(const u_char *,int*,int*,int);

int ipv4(const u_char *,int*,int*,int);

void arp(const u_char *,int);

#endif