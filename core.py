#!/usr/bin/python

from sys import stdin
import socket
import threading
from scapy.all import *
from scapy.error import Scapy_Exception
from netaddr import *
import time
from help import *
from menu import *
from arp import *
from icmp import *
from stats import *
from rip import *
from route import *


NULL = 0

eth0 = {}
eth1 = {}



port1 = "eth2"
port2 = "eth3"
table = {}
arp_table = {}
rip_table = []
rip_en = False
port = ""
th = 0
flag = 0
iterator = 0
stats = Stat()

def rip_up_send():
	while(True):
		if rip_en is not False:
		
			send_time_request(rip_networks,route_table,rip_ifaces)
			time.sleep(30)

def rip_timers():
	while(True):
		if rip_en is not False:
			global route_table
			time.sleep(1)
			for r in route_table:
				if r['protocol'] == 'R':	
					# int(r['timer']) -= 1
					if r['timer'] == 180: # TODO time
						pass
						# zmen ma na invalida
					if r['timer'] == 0: # TODO time
						pass
						# vymaz ma
					if r['active'] is True and r['metric'] == 16:
						# dosla mi poison a nieco musim spravit
						r['active'] = False




def set_rip_iface():
	global rip_ifaces
	for r in route_table:
		for net in rip_networks:
			if r['network'] == net:
				rip_ifaces.append({'int' : str(r['int']),'IP' : str(r['eth_IP'])})
	# print rip_ifaces


def update_ARP_table(IP,MAC):
	lock.acquire()
	arp_table.update({IP: [MAC]})
	lock.release()

def updateTable(port, srcMAC, thread):
    lock.acquire()
    table.update({srcMAC: [port, time.time(), 10]})
    lock.release()


def get_from_arp(dstIP):
	lock.acquire()
	if arp_table.has_key(dstIP):
		lock.release()
		return str(arp_table[dstIP][0])
	else:
		lock.release()
		return False
	lock.release()

def getPort(dstMac, thread):
	lock.acquire()
	if table.has_key(dstMac):
		lock.release()
            	return table[dstMac]
	lock.release()

def get_arp(pkt, ethIP,ifaceFrom):
	print "mam arp paket"
	if ARP in pkt and pkt[ARP].pdst == ethIP and pkt[ARP].op == 2 : # is-at                
		print "paket je response"
		update_ARP_table(pkt[ARP].psrc, pkt[ARP].hwsrc)
		return pkt[ARP].hwsrc	
	if ARP in pkt and pkt[ARP].pdst == ethIP and pkt[ARP].op == 1: # who-has
		print "paket je request na mna"
		update_ARP_table(pkt[ARP].psrc, pkt[ARP].hwsrc)
		arp = send_ARP_reply(ethIP, pkt)
		sendp (arp, iface = ifaceFrom, verbose = 0)
		print arp.show()
		return False
	if ARP in pkt and pkt[ARP].pdst != ethIP:
		print "mam cudzie arp"
		update_ARP_table(pkt[ARP].psrc,pkt[ARP].hwsrc)
		route = check_route(pkt[ARP].pdst)
		arp = send_ARP_reply(ethIP, pkt)
		#  print pkt.show()
		if route is not False:
			print "idem odoslat rep na cudzie arp na ", ifaceFrom,arp.show() 
			sendp(arp, iface = ifaceFrom ,verbose = 0)
			return False
			

def check_route(dstIP):
	for route in route_table:
		flag = IPAddress(str(dstIP)) in IPNetwork(route['network'])
		if flag is True and route['active'] is True:
			print "Debug, mam zhodu na: ",str(route['network']),str(route['int'])
			return route
	return False
					


def rcv(ifaceFrom, ifaceTo, thread):
	global stats
    	socks = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    	socks.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
    	socks.bind((ifaceFrom, ETH_P_ALL))
	# print "Cnucham na porte ", ifaceFrom 
	while (True):
        	if ifaceFrom == "eth2":
                	global eth0_IP
               		ethIP = eth0_IP
        	else:
                	global eth1_IP
                	ethIP = eth1_IP

		packet, info = socks.recvfrom(MTU)        
		if (info[2] != socket.PACKET_OUTGOING):
			# update stats
			stats = update_stats("in",ifaceFrom, stats)
		#	packet, info = socks.recvfrom(MTU)
        		paketik = Ether(packet)
			# print "Catch on int: ", ifaceFrom
			# print paketik.summary()
			if ARP in paketik:
				# print "Debug idem do funkcie ARP"
        			get_arp(paketik,ethIP,ifaceFrom)
				print "Odoslal som arp"
			if ICMP in paketik and paketik[IP].dst == eth0_IP or (ICMP in paketik and paketik[IP].dst == eth1_IP):
				print "Debug prisiel ICMP"
				pkt = send_ICMP_reply(paketik,ethIP)
				sendp(pkt, iface=ifaceFrom, verbose = 0)
			if RIP in paketik and rip_en is True:
				# print "mam rip"
				for i in rip_ifaces:
					# print "RIP ", i['int'], ifaceFrom
					if ifaceFrom == i['int']:
						rip_routes  = get_from_rip(paketik, ifaceFrom)
        					update_route_table(rip_routes, "R")
			if (RIP not in paketik and IP in paketik and paketik[IP].dst != eth0_IP and (IP in paketik and paketik[IP].dst != eth1_IP)):
				print "Debug prisiel IP paket na smerovanie"
        			route = check_route(paketik[IP].dst)
				if route is not False:
					dstMAC = get_from_arp(route['next-hop'])
					if dstMAC is not False:
						print "idem posielat na: ",str(route['int'])
						pkt = paketik
						hlp_dst = paketik.getfieldval('dst')
						pkt[Ether].dst = dstMAC
						pkt[Ether].src = hlp_dst
						# TODO decrement ttl
						try:
							print pkt.show()
							sendp(pkt,iface=ifaceTo, verbose = 0)
						except Scapy_Exception as msg:
        						print msg, "Chyba pri odosielani na druhy iface"
					else:
						arp = send_ARP_req(route['eth_IP'],route['next-hop'])
                                                try:
                                                        sendp(arp,iface=ifaceTo, verbose = 0)
                                                except Scapy_Exception as msg:
                                                        print msg, "Chyba pri odosielani na druhy iface"
						print "nemam ARP ziadam ARP na", route['next-hop'] , arp.show()

			# print "Koncim"


####--------MAIN-----------####
			
def thr1():
	rcv(port1, port2, t1)
def thr2():
    rcv(port2, port1, t2)
#def thr3():
#    down()

lock = threading.Lock()
def thr4():
	rip_up_send()
def thr5():
	rip_timers()

t1 = threading.Thread(target = thr1 )
t2 = threading.Thread(target = thr2 )
#t3 = threading.Thread(target = thr3)
t_rip = threading.Thread(target = thr4)
t_rip_time = threading.Thread(target = thr5)
t1.start()
t2.start()
#time.sleep(1)
#t3.start()

route = {}
route.update({'active': True,'network':'10.10.10.0/24','next-hop':'10.10.10.10','protocol':'C','metric':'1', 'int':'eth2', 'eth_IP':'10.10.10.1'})

route_table.append(route)
route = {}
route.update({'active': True, 'network':'20.20.20.0/24','next-hop':'20.20.20.20','protocol':'C','metric':'1', 'int':'eth3', 'eth_IP':'20.20.20.1'})

route_table.append(route)



while(True):
	command = raw_input('R1(config)#')
    	if(command == "exit"):
        	t1._Thread__stop()
        	t2._Thread__stop()
		t_rip._Thread__stop()
		t_rip_time._Thread__stop()
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
		menu_eth0(port1)
	if (command == "int eth1"):
		menu_eth1(port2)
	if (command == "show ip route"):
		for route in route_table:
			print route['protocol']+"      "+route['network']+"   nexthop " +route['next-hop']+ "  on "+ route['int'] + "   metric: "  + route['metric'] + "   active: " + str(route['active'])
	if (command == "ip route"):
		net = raw_input("Network(IP/prefix):")
		next_hop = raw_input("Next-hop(IP):")
		interface = raw_input("Interface(eth):")
		route = {}
		route.update({'network':net,'next-hop': next_hop,'protocol':'S','metric':'1', 'int':interface})
		route_table.append(route)	
	if (command == "router rip"):
		rip_table = menu_rip()
		set_rip_iface()
		if iterator is 0: 
			t_rip.start()
			t_rip_time.start()
		rip_en = True
		iterator += 1
	if (command == "no router rip"):
		rip_en = False
		del rip_networks[:]
		del rip_ifaces[:]
		# t_rip._Thread__stop()
	if (command == "show rip"):
		print "----RIP information base----"
		print "!"
		print "RIPv2 enable: ",rip_en
		print "RIP active interfaces: ",rip_ifaces
		print "RIP local networks: ", rip_networks
		print "!"
	if (command == "show st" or command == "show statistics"):
		print "In/Out statistics on ports"
		print "Eth0 in:", stats.eth0_in
		print "Eth0 out: ", stats.eth0_out
                print "Eth1 in:", stats.eth1_in
                print "Eth1 out: ", stats.eth1_out
	if (command == "reset st"):
		reset_stats()







