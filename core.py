#!/usr/bin/python

from sys import stdin
import socket
import threading
from scapy.all import *
import time
from help import *
from menu import *

NULL = 0


eth0_IP = NULL
eth1_IP = NULL

port1 = "eth2"
port2 = "eth3"
table = {}
port = ""
th = 0
flag = 0

# port = zdrojovy port, srcMAC = zdrojova Mac packetu, tread = vlakno ktore checkuje


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


def getPort(dstMac, thread):
	lock.acquire()
	if table.has_key(dstMac):
#       	print "Nasiel som ",table[dstMac]
        #port = table[dstMac]
		lock.release()
            	return table[dstMac]
	lock.release()

def rcv(ifaceFrom, ifaceTo, thread):
    	socks = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    	socks.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
    	socks.bind((ifaceFrom, ETH_P_ALL))
	print "Cnucham na porte ", ifaceFrom 
	while (True):
		packet, info = socks.recvfrom(MTU)        
		if (info[2] != socket.PACKET_OUTGOING):
		#	packet, info = socks.recvfrom(MTU)
        		paketik = Ether(packet)
        		print ("Zachyteny z ",ifaceFrom,paketik.getfieldval('dst'), paketik.getfieldval('src'))
			updateTable(ifaceFrom, paketik.getfieldval('src'), thread)
        		pomoc = paketik.getfieldval('dst')
        		portTarget = getPort(pomoc, thread)
        		if (info[2] != socket.PACKET_OUTGOING ):
        			if portTarget:
                			sendp(paketik, iface = portTarget[0], verbose = 0)
                			flag = 0
#                			print "Poslal som najdeny, " ,ifaceFrom, ifaceTo
            			else:
                			sendp(paketik, iface = ifaceTo, verbose = 0)
#                			print "Nenajdeny som odoslal",ifaceFrom,ifaceTo

def thr1():
    rcv(port1, port2, t1 )
def thr2():
    rcv(port2, port1, t2)
def thr3():
    down()
lock = threading.Lock()

t1 = threading.Thread(target = thr1 )
t2 = threading.Thread(target = thr2 )
#t3 = threading.Thread(target = thr3)

#time.sleep(1)
#t1.start()
#time.sleep(1)
#t2.start()
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
		menu_eth0()
	
			


