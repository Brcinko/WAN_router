from sys import stdin 
from route import *

eth0 = {}
eth1 = {}
rip_networks = []

eth0_IP = "10.10.10.1"
eth1_IP = "20.20.20.1"

port1 = "eth2"
port2 = "eth3"


def menu_eth0(port):
	print "CONFIG-IF eth0"
	while(True):
                #print "DEBUG second while"
                comm = raw_input('R1(conf-if)#')
                if (comm == "?"):
                       	print "ip add<cr>  then bring up with \"no sh\" "
                if (comm == "no sh"  and  eth0_IP is not NULL):
                        eth0['shutdwon'] = False
                if (comm == "sh" or comm == "shutdown"):
			deactivate_connected_route(port1)
                if (comm == "ip add"):
                        print "Set IP (A.B.C.D)"
                        eth0_IP = raw_input()
                        print "Set mask: "
                        eth0['mask'] = raw_input()
			eth0['int'] = port
			eth0['metric'] = 1
			eth0['IP'] = eth0_IP
			eth0['protocol'] = 'C'
			eth0['active'] = True
			print "Set next-hop: "
			eth0['next-hop'] = raw_input()
			update_static_route(eth0)	
                if (comm == "ex" or comm == "exit"):
                        break
#	return eth0


def menu_eth1(port):
	print "CONFIG-IF eth1"
	while(True):
		#print "DEBUG second while"
                comm = raw_input('R1(conf-if)#')
                if (comm == "?"):
                	print "ip add<cr>  then bring up with \"no sh\" "
                if (comm == "no sh"  and  eth0_IP is not NULL):
                        eth1['shutdown'] = False
                if (comm == "sh" or comm == "shutdown"):
                        deactivate_connected_route(port2)
                if (comm == "ip add"):
                        print "Set IP (A.B.C.D)"
                        eth1_IP = raw_input()
                        print "Set mask: "
                        eth0['mask'] = raw_input()
                        eth0['int'] = port
                        eth0['metric'] = 1
                        eth0['IP'] = eth0_IP
                        eth0['protocol'] = 'C'
			eth0['active'] = True
			print "Set netxt-hop: "
			eth0['next-hop'] = raw_input()
                        update_static_route(eth0)

                if (comm == "ex" or comm == "exit"):
                        break
# 	return eth1


def menu_rip():
	while(True):
		comm = raw_input('R1(config-router)#')
		if (comm == "?"):
			print "try network<cr> and dont forget no auto-summary!!"
		if (comm == "network" or comm == "net"):
			net = raw_input('IP_Address/Prefix:')
			rip_networks.append(net)
		if (comm == "no network"):
                        net = raw_input('IP_Address/Prefix:')
                        rip_networks.remove(net)
		if (comm == "ex" or comm =="exit"):
			# pass
			return
		if (comm == "no auto-summary"):
			print "Chvalabohu"
				

