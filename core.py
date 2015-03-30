#!/usr/bin/python

from sys import stdin
import socket
import threading
from scapy.all import *
import time
from help import *
from menu import *
from arp import *

NULL = 0

eth0 = {}
eth1 = {}


eth0_IP = "10.10.10.2" 
eth1_IP = NULL



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
	lock.release()

def getPort(dstMac, thread):
	lock.acquire()
	if table.has_key(dstMac):
		lock.release()
            	return table[dstMac]
	lock.release()

def arp(socks, ethIP):
	while(True):
		packet, info = socks.recvfrom(MTU)
        	if (info[2] != socket.PACKET_OUTGOING):
        	#       packet, info = socks.recvfrom(MTU)
        		paketik = Ether(packet)
			if ARP in pkt and pkt[ARP].pdst == ethIP and pkt[ARP].op in (2): # is-at                
				update_ARP_table(pkt[ARP].pdst,pkt[ARP].hwsrc)
				return pkt[ARP].hwsrc	



def rcv(ifaceFrom, ifaceTo, thread, ethIP):
    	socks = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    	socks.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
    	socks.bind((ifaceFrom, ETH_P_ALL))
	print "Cnucham na porte ", ifaceFrom 
	while (True):
		packet, info = socks.recvfrom(MTU)        
		if (info[2] != socket.PACKET_OUTGOING):
		#	packet, info = socks.recvfrom(MTU)
        		paketik = Ether(packet)
			if IP in paketik:
        			pass
			updateTable(ifaceFrom, paketik.getfieldval('src'), thread)
        		pomoc = paketik.getfieldval('dst')
        		portTarget = getPort(pomoc, thread)
        		if (info[2] != socket.PACKET_OUTGOING ):
        			if portTarget:
                			get_from_arp("10.10.10.1")
					send_ARP_req(ethIP,"10.10.10.1")
					dstMAC = (socks, ethIP)
					# treba vyriesit odosielanie na MAC
					sendp(paketik, iface = portTarget[0], verbose = 0)
                			flag = 0
#                			print "Poslal som najdeny, " ,ifaceFrom, ifaceTo
            			else:
                			print "SOMTU!!!"
                                        get_from_arp("10.10.10.1")
                                        send_ARP_req(ethIP,"10.10.10.1")
                                        dstMAC = (socks, ethIP)

					sendp(paketik, iface = ifaceTo, verbose = 0)
#                			print "Nenajdeny som odoslal",ifaceFrom,ifaceTo

def thr1():
    	# send_ARP_req("10.10.10.2", "10.10.10.1")
	rcv(port1, port2, t1, eth0_IP )
def thr2():
    rcv(port2, port1, t2, eth0_IP )
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

while(True):
	command = stdin.readline()
    	if(command == "exit\n"):
        	t1._Thread__stop()
        	t2._Thread__stop()
        #t3._Thread__stop()
        	quit()
	if(command == "table\n"):
		print table
	if(command == "reset\n"):
		table = {}
	if (command == "help\n"):
		help()
	if (command == "int eth0\n"):
		eth0 = menu_eth0()
	if (command == "int eth1\n"):
		eth1 = menu_eth1()
	
			


