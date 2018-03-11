#ifndef CAPTURE_H
#define CAPTURE_H
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <sys/types.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <unistd.h>
#include <stdbool.h>
#include "transport.h"
#include "application.h"
#include "liaison.h"
#include "reseau.h"

extern char *optarg;

#define VERBOSE_COMPLET  3 //verbosité par défault
#define VERBOSE_MOYEN 2
#define VERBOSE_FAIBLE 1
#define STRING_SIZE 256
#define HTTP_PORT 80
#define SMTP_PORT 25
#define IMAP_PORT 143
#define POP_PORT 110
#define TELNET_PORT 23
#define DNS_PORT 53
#define FTP_CONTROL_PORT 21
#define FTP_DATA_PORT 20
#define DHCP_CLIENT_PORT 68
#define DHCP_SERVER_PORT 67
#define HTTPS_PORT 443


void got_packet(u_char *, const struct pcap_pkthdr 
*, const u_char *);



void output_header(char*,int);

#endif






