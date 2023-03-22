#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include "libnet-headers.h"
#include <stdlib.h>
#include <arpa/inet.h>

#define ETHERNET_SIZE 14

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {


	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		printf("------------------------------------------------------\n");
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);


	struct libnet_ethernet_hdr * eth;
	eth = (struct libnet_ethernet_hdr *)packet; 
	printf("Src Mac : ");
	for(int i=0;i<6;i++)printf("%02x",eth->ether_shost[i]);
	printf(" 		Dst Mac : ");
	for(int i=0;i<6;i++)printf("%02x",eth->ether_dhost[i]);

	printf("\n");

	if(eth->ether_type == 8){
		printf("yes IPv4\n");	
		struct libnet_ipv4_hdr* ip; 
		ip = (struct libnet_ipv4_hdr*)(packet + ETHERNET_SIZE);

		printf("ip_src : %s\n",inet_ntoa(ip->ip_src));
		printf("ip_dst : %s\n",inet_ntoa(ip->ip_dst));
		int IP_SIZE = 4*(ip->ip_hl);
			struct libnet_tcp_hdr * tcp = (struct libnet_tcp_hdr*)(packet + ETHERNET_SIZE + IP_SIZE);
			printf("tcp stc port : %d\n",ntohs(tcp->th_sport));
			printf("tcp dst port : %d\n",ntohs(tcp->th_dport));

			printf("payload is : ");
			int TCP_SIZE = (tcp->th_off)*4;
			u_char* payload = (u_char*)(packet + ETHERNET_SIZE + IP_SIZE + TCP_SIZE);
			int datasize = header->caplen - ETHERNET_SIZE - IP_SIZE - TCP_SIZE;
			datasize = datasize < 10 ? datasize : 10; 
			for(int i=0;i<datasize;i++) printf("%02x",payload[i]);
			printf("\nend\n");
	}

	printf("------------------------------------------------------\n\n\n");

	}

	pcap_close(pcap);
}
