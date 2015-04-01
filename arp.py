from scapy.all import *


def check_ARP_table(IP, ARP_table):
	pass

def send_ARP_req(srcIP,dstIP):
	pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP( pdst=dstIP, psrc= srcIP, op= "who-has")
	# print pkt.show()
	return pkt


def recieve_ARP_rep(port):
	pass


def send_ARP_reply(ethIP, arp_req):
	pkt = Ether(dst=arp_req[ARP].hwsrc)/ARP(psrc=ethIP, hwdst=arp_req[ARP].hwsrc,pdst=arp_req[ARP].psrc,op="is-at")
	return pkt
