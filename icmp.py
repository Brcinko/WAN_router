from scapy.all import *



def send_ICMP_reply(pkt,ethIP):
	icmp_pkt = Ether(dst=pkt.getfieldval('src'))/IP(dst = pkt[IP].src, src = ethIP)/ICMP(type="echo-reply", id = pkt[ICMP].id, seq = pkt[ICMP].seq)/Raw(pkt[Raw])

	return icmp_pkt
