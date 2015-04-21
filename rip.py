# __author__= "brcinko"
from scapy.all import *
from netaddr import *

"""
route_table: 
	[{'network':'10.10.10.0/24','next-hop':'10.10.10.10','protocol':'C','metric':'1', 'int':'eth0', 'eth_IP':'10.10.10.1'}]

rip_base: '10.10.10.0/24'
"""

def send_time_request(rip_base,route_table,iface1,iface2, p1_IP, p2_IP):
	routes = []
	# paketik = 
	routes = get_rip_routes(rip_base, route_table)
	# routes = update_metric(routes)
	# print routes
	entry = IPNetwork(routes[0]['network'])

	eth = Ether()
	ip = IP()
	ip.src= p1_IP
	ip.dst='224.0.0.9'
	ip.ttl = 1
	u = UDP(sport=520, dport=520)
	rh = RIP(cmd='resp', version=2)
	pkt = eth/ip/u/rh	
	for route in routes:
		entry = IPNetwork(route['network'])
		mtr = (int(route['metric']) + 1) if route['metric'] < 16 else 16
		r = RIPEntry(addr = str(entry.network), mask = str(entry.netmask), metric = mtr)	
		pkt /=r
	sendp(pkt,iface = iface1, verbose = 1)
	# print pkt.show(pkt)

def get_rip_routes(rip_base,route_table):
	routes = []
	for r in route_table:
		for net in rip_base:
			if r['network'] == net:
				routes.append({'network': net,'metric' : str(r['metric'])})
	return routes
	# print routes

