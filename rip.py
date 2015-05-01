# __author__= "brcinko"
from scapy.all import *
from netaddr import *

"""
route_table: 
	[{'network':'10.10.10.0/24','next-hop':'10.10.10.10','protocol':'C','metric':'1', 'int':'eth0', 'eth_IP':'10.10.10.1'}]

rip_base: '10.10.10.0/24'
"""
"""
rip_routes:


"""

rip_ifaces = []
poison_time = 120

################################
###Its response actually########
################################

def send_time_request(rip_base,route_table,ifaces):
	routes = []
	routes = get_rip_routes(rip_base, route_table)
	# routes = update_metric(routes)
	# print routes
	for iface in ifaces:
		eth = Ether()
		ip = IP()
		ip.src= str(iface['IP'])
		ip.dst='224.0.0.9'
		ip.ttl = 1
		u = UDP(sport=520, dport=520)
		rh = RIP(cmd='resp', version=2)
		pkt = eth/ip/u/rh	
		for route in routes:
			if str(route['protocol']) == 'R' and str(iface['int']) == str(route['int']):
				pass
			else:
				entry = IPNetwork(route['network'])
				mtr = (int(route['metric']) + 1) if int(route['metric']) < 16 else 16
				r = RIPEntry(addr = str(entry.network), mask = str(entry.netmask), metric = mtr)	
				pkt /=r
		eth = str(iface['int'])
		eth = ''.join(eth.split())
		# print "sending rip on", eth
		sendp(pkt,iface = eth, verbose = 0)
	# print pkt.show(pkt)

def get_rip_routes(rip_base,route_table):
	routes = []
	for r in route_table:
		if r['protocol'] != 'S': # and is in rip base
			routes.append({'network': r['network'],'metric' : str(r['metric']), 'int': str(r['int']), 'protocol': r['protocol']})
	print routes
	return routes


def get_from_rip(pkt, iface):
	# print pkt.show()
	routes = []	
	for entry in pkt[RIPEntry]:
		# print entry.show()
		if str(entry.metric) is not '16':
			r = {'network': str(entry.addr), 'metric' : str(entry.metric), 'int': iface, 'netmask': str(entry.mask), 'next-hop' : str(entry.nextHop)}
			routes.append(r)
		else:
			pass
			for iface in ifaces:
                		eth = Ether()
                		ip = IP()
                		ip.src= str(iface['IP'])
                		ip.dst='224.0.0.9'
                		ip.ttl = 1
                		u = UDP(sport=520, dport=520)
                		rh = RIP(cmd='resp', version=2)
                		pkt = eth/ip/u/rh
                		pkt /= entry
                		eth = str(iface['int'])
                		eth = ''.join(eth.split())
                		# print "sending rip on", eth
                		sendp(pkt,iface = eth, verbose = 0)

	# print routes
	return routes


	
def send_poison(route,ifaces):


	for iface in ifaces:
                eth = Ether()
                ip = IP()
                ip.src= str(iface['IP'])
                ip.dst='224.0.0.9'
                ip.ttl = 1
                u = UDP(sport=520, dport=520)
                rh = RIP(cmd='resp', version=2)
                pkt = eth/ip/u/rh
                entry = IPNetwork(route['network'])
                r = RIPEntry(addr = str(entry.network), mask = str(entry.netmask), metric = 16)
               	pkt /=r
		eth = str(iface['int'])
                eth = ''.join(eth.split())
                # print "sending rip on", eth
                sendp(pkt,iface = eth, verbose = 0)



