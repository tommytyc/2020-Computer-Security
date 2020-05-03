import socket
from scapy.all import *
import netifaces

def ScanDevices(dst_addr, src_addr, gateway_addr):
    eth = Ether(dst = "ff:ff:ff:ff:ff:ff")
    arp = ARP(psrc = src_addr, pdst = dst_addr)
    pkt = eth/arp
    result = srp(pkt, timeout = 1, verbose = False)[0]
    
    print('-'*41)
    print('IP\t\t\tMAC Address')
    print('-'*41)

    client_list = []
    AP_info = {}
    for element in result:
        client = {'ip': element[1].psrc, 'mac': element[1].hwsrc}
        if element[1].psrc != gateway_addr:
            print(element[1].psrc + '\t\t' + element[1].hwsrc)
            client_list.append(client)
        else:
            AP_info = client
    
    return client_list, AP_info


routingGateway = netifaces.gateways()['default'][netifaces.AF_INET][0]
routingNicName = netifaces.gateways()['default'][netifaces.AF_INET][1]

for interface in netifaces.interfaces():
    if interface == routingNicName:
        routingNicMacAddr = netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]['addr']
        try:
            routingIPAddr = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
            routingIPNetmask = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['netmask']
        except KeyError:
            pass

scan_dst = str(routingGateway) + '/' + str(sum(bin(int(x)).count('1') for x in routingIPNetmask.split('.')))
client_list, AP_info = ScanDevices(scan_dst, routingIPAddr, routingGateway)

