from scapy.all import *


def check_ARP_table(IP, ARP_table):
	pass

def send_ARP_req(srcIP,dstIP):
	pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP( pdst=dstIP, psrc= srcIP, op= "who-has")
	print pkt.show()

def recieve_ARP_rep(port):
	pass
	socks = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        socks.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
        socks.bind((ifaceFrom, ETH_P_ALL))
	while(True):
		pass



