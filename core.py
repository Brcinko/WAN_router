#!/usr/bin/python

from sys import stdin
import socket
import threading
from scapy.all import *
from netaddr import *
import time
from help import *
from menu import *
from arp import *
from icmp import *


NULL = 0

eth0 = {}
eth1 = {}


eth0_IP = "10.10.10.1" 
eth1_IP = "20.20.20.1"

route_table = []

port1 = "eth2"
port2 = "eth3"
table = {}
arp_table = {}
port = ""
th = 0
flag = 0


# port = zdrojovy port, srcMAC = zdrojova Mac packetu, tread = vlakno ktore checkuje

def update_ARP_table(IP,MAC):
	lock.acquire()
	arp_table.update({IP: [MAC]})
	lock.release()

def updateTable(port, srcMAC, thread):
    lock.acquire()
    table.update({srcMAC: [port, time.time(), 10]})
    lock.release()


def down():
    lock.acquire()
    for pom in table:
        minus = table[pom][2] - 1
        table[pom][2] = minus
        if(table[pom][2] == 0):
            del table[pom]
            break
    lock.release()
    time.sleep(1)


def get_from_arp(dstIP):
	lock.acquire()
	if arp_table.has_key(dstIP):
		lock.release()
		return arp_table[dstIP]
	else:
		return False
	lock.release()

def getPort(dstMac, thread):
	lock.acquire()
	if table.has_key(dstMac):
		lock.release()
            	return table[dstMac]
	lock.release()

def arp(pkt, ethIP,ifaceFrom):
	print "mam arp paket"
	if ARP in pkt and pkt[ARP].pdst == ethIP and pkt[ARP].op == 2 : # is-at                
		print "paket je response"
		update_ARP_table(pkt[ARP].psrc, pkt[ARP].hwsrc)
		return pkt[ARP].hwsrc	
	if ARP in pkt and pkt[ARP].pdst == ethIP and pkt[ARP].op == 1: # who-has
		print "paket je request na mna"
		update_ARP_table(pkt[ARP].psrc, pkt[ARP].hwsrc)
		pkt = send_ARP_reply(ethIP, pkt)
		sendp (pkt, iface = ifaceFrom, verbose = 0)
		return False
	if ARP in pkt and pkt[ARP].pdst != ethIP:
		print "mam cudzie arp"
		update_ARP_table(pkt[ARP].psrc,pkt[ARP].hwsrc)
		route = check_route(pkt[ARP].pdst)
		arp = send_ARP_req("20.20.20.1", pkt[ARP].pdst)
		#  print pkt.show()
		if route is not False:
			lock.acquire()
			sendp(pkt,iface = str(route['int']),verbose = 0)
			lock.release()

def check_route(dstIP):
	for route in route_table:
		flag = IPAddress(str(dstIP)) in IPNetwork(route['network'])
		if flag is True:
			print "Debug, mam zhodu na: ",str(route)
			return route
	return False
					


def rcv(ifaceFrom, ifaceTo, thread, ethIP):
    	socks = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    	socks.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
    	socks.bind((ifaceFrom, ETH_P_ALL))
	# print "Cnucham na porte ", ifaceFrom 
	while (True):
		packet, info = socks.recvfrom(MTU)        
		if (info[2] != socket.PACKET_OUTGOING):
		#	packet, info = socks.recvfrom(MTU)
        		paketik = Ether(packet)
			if ARP in paketik:
				# print "Debug idem do funkcie ARP"
        			arp(paketik,ethIP,ifaceFrom)
			if ICMP in paketik:
				print "Debug prisiel ICMP"
				pkt = send_ICMP_reply(paketik,ethIP)
				sendp(pkt, iface=ifaceFrom, verbose = 0)
			updateTable(ifaceFrom, paketik.getfieldval('src'), thread)
        		pomoc = paketik.getfieldval('dst')
        		portTarget = getPort(pomoc, thread)
        		if (IP in paketik and paketik[IP].dst != ethIP ):
				print "Debug prisiel IP paket"
        			route = check_route(paketik[IP].dst)
				if route is not False:
					dstMAC = get_from_arp(route['next-hop'])
					if dstMAC is not False:
						pkt = paketik
						pkt[Ether].dst = dstMAC
						pkt[Ether].src = paketik[Ether].dst
						# TODO decrement ttl
						sendp(pkt,iface=route['int'],verbose=0)
					else:
						send_ARP_req(ethIP,route['next-hop'])
						
#				if portTarget:
#                			get_from_arp("10.10.10.1")
#					send_ARP_req(ethIP,"10.10.10.1")
#					dstMAC = (socks, ethIP)
#					# treba vyriesit odosielanie na MAC
#					sendp(paketik, iface = portTarget[0], verbose = 0)
#                			flag = 0
#                			print "Poslal som najdeny, " ,ifaceFrom, ifaceTo
#            			else:
#                			# print "SOMTU!!!"
#                                       get_from_arp(str(paketik[IP].dst))
#                                       arp_pkt = send_ARP_req(ethIP,"10.10.10.25")
#                                       dstMAC = (socks, ethIP)
#					sendp (arp_pkt, iface = ifaceTo, verbose = 0)
#					sendp(paketik, iface = ifaceTo, verbose = 0)
#                			print "Nenajdeny som odoslal",ifaceFrom,ifaceTo

def thr1():
	rcv(port1, port2, t1, eth0_IP )
def thr2():
    rcv(port2, port1, t2, eth1_IP )
def thr3():
    down()
lock = threading.Lock()

t1 = threading.Thread(target = thr1 )
t2 = threading.Thread(target = thr2 )
#t3 = threading.Thread(target = thr3)

time.sleep(1)
t1.start()
time.sleep(1)
t2.start()
#time.sleep(1)
#t3.start()

route = {}
route.update({'network':'10.10.10.0/24','next-hop':'10.10.10.10','protocol':'C','metric':'1', 'int':'eth0'})

route_table.append(route)
route = {}
route.update({'network':'20.20.20.0/24','next-hop':'20.20.20.20','protocol':'C','metric':'1', 'int':'eth1'})

route_table.append(route)



while(True):
	command = raw_input('R1(config)#')
    	if(command == "exit"):
        	t1._Thread__stop()
        	t2._Thread__stop()
        #t3._Thread__stop()
        	quit()
	if(command == "table"):
		print table
	if(command =="show arp table"):
		print " IP              MAC"		
		print arp_table
	if(command == "reset"):
		table = {}
	if (command == "help"):
		help()
	if (command == "int eth0"):
		eth0 = menu_eth0()
	if (command == "int eth1"):
		eth1 = menu_eth1()
	if (command == "show ip route"):
		for route in route_table:
			print route['protocol']+"      "+route['network']+"   nexthop " +route['next-hop']+ "  on "+ route['int']  
	if (command == "ip route"):
		net = raw_input("Network(IP/prefix):")
		next_hop = raw_input("Next-hop(IP):")
		interface = raw_input("Interface(eth):")
		route = {}
		route.update({'network':net,'next-hop': next_hop,'protocol':'S','metric':'1', 'int':interface})
		route_table.append(route)	


