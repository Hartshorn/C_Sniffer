#ifndef SNIFFER_H
#define SNIFFER_H


#define HAVE_REMOTE

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>

#include <pcap.h>

#define LINE_LEN    16

void show_devicelist_info(pcap_if_t *);
void show_device_info(pcap_if_t *, int);
pcap_if_t* interface_handler(pcap_if_t *, unsigned char*);

void process_packet(unsigned char*, int);
void print_ethernet_header(unsigned char*);
void print_ip_header(unsigned char*, int);
void print_tcp_header(unsigned char*, int);
void print_udp_packet(unsigned char*, int);
void print_icmp_packet(unsigned char*, int);
void print_data(unsigned char*, int);

struct ethernet_header
{
    unsigned char dest[6];
    unsigned char source[6];
    unsigned short type;
};

/* the :4 defines the bit field width */
struct ip_header
{
	unsigned char ip_version:	4;	/* version: 4 bits */
	unsigned char ip_header_len:	4;	/* header length: 4 bits */
	unsigned char ip_tos;			/* ip type of service: 8 bits */
	unsigned short ip_total_length;		/* total length: 16 bits */
	unsigned short ip_id;			/* identification: 16 bits */

	unsigned char ip_frag_offset:	5;	/* fragment offset field: 5 bits */

	unsigned char ip_more_fragment: 1;	/* parts of */
	unsigned char ip_dont_fragment: 1;	/* the fragment */
	unsigned char ip_reserved_zero: 1;	/* field */

	unsigned char ip_frag_offset1;		/* fragement offset */

	unsigned char ip_ttl;			/* time to live: 8 bits */
	unsigned char ip_protocol;		/* TCP UDP - Protocol field: 8 bits */
	unsigned short ip_checksum;		/* header checksum: 16 bits */
	unsigned int ip_srcaddr;		/* source: 32 bits */
	unsigned int ip_destaddr;		/* destination: 32 bits */

};

struct udp_header
{
	unsigned short source_port;		/* source port number */
	unsigned short dest_port;		/* destination port */
	unsigned short udp_length;		/* udp packet length */
	unsigned short udp_checksum;		/* udp checksum (optional) */
};

struct tcp_header
{
	unsigned short source_port;		/* source port */
	unsigned short dest_port;		/* destination port */
	unsigned int sequence;			/* sequence number: 32 bits */
	unsigned int acknowledge;		/* acknowledgement number: 32 bits */

	unsigned char ns: 1;			/* nonce(?) sum flag (RFC 3540) */
	unsigned char reserved_part1: 3;	/* according to the RFC */
	unsigned char data_offset: 4;		/* the number of 32 bit words in the TCP header -
						   indicates where the data begins - the length
						   of the tcp header is always a multiple of 32 bits */

	unsigned char fin: 1;			/* finish flag */
	unsigned char syn: 1;			/* synchronize flag */
	unsigned char rst: 1;			/* reset flag */
	unsigned char psh: 1;			/* push flag */
	unsigned char ack: 1;			/* acknowlegment flag */
	unsigned char urg: 1;			/* urgent flag */

	unsigned char ecn: 1;			/* ECN-echo flag */
	unsigned char cwr: 1;			/* congestion window reduced flag */

	unsigned short window;			/* window */
	unsigned short checksum;		/* checksum */
	unsigned short urgent_pointer;		/* urgent pointer */
};

struct icmp_header
{
	unsigned char  type;                    /* ICMP error type */
	unsigned char  code;			/* type sub code */
	unsigned short checksum;		/* checksum */
	unsigned short id;			/* id */
	unsigned short seq;			/* sequence */
};
#endif

