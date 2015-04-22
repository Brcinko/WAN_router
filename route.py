# __author__ = 'brcinko'
from netaddr import *
from rip import *

"""
route_table:
        [{'network':'10.10.10.0/24','next-hop':'10.10.10.10','protocol':'C','metric':'1', 'int':'eth0', 'eth_IP':'10.10.10.1'}]
"""


route_table = []

def find_index(routes):
        i = 0
        for r in route_table:
                for ro in routes:
                        ip = IPNetwork(str(ro['network']) + '/' + str(ro['netmask']))
                        n = ip.prefixlen
                        net = str(ro['network']) + '/' + str(n)
                        # print "Kontrolujem prvu moju ", r['network'], net, i
                        if r['network'] == net:
                                return i
                i += 1
        return False


def update_route_table(routes, proto):
        # remove old duplicates
        index = find_index(routes)
        if index is not False:
                route_table.pop(index)
        # print routes
        for r in routes:
                # set all parameters
                ip = IPNetwork(str(r['network']) + '/' + str(r['netmask']))
                n = ip.prefixlen
                net = str(r['network']) + '/' + str(n)
                # set ethIP 
                for i in rip_ifaces:
                        if r['int'] == i['int']:
                                ethIP = i['IP']
                route = {'timer' : 240 , 'active': True, 'network' : net , 'next-hop' : r['next-hop'], 'metric' : r['metric'], 'protocol' : proto, 'int' : r['int'], 'eth_IP' : ethIP}
                route_table.append(route)




def set_route(eth):
	print eth
	hlpstr = str(eth['IP']) + '/' + str(eth['mask'])
	ip = IPNetwork(hlpstr)
	net = str(ip.network) + '/' + str(ip.prefixlen)
	route = {}
	route.update({'actve': True ,'network': net, 'next-hop': '0.0.0.0', 'protocol': eth['protocol'], 'metric': str(eth['metric']), 'int': eth['int'], 'eth_IP': eth['IP']})
	
	return route

def old_index(eth):
	i = 0
	for r in route_table:
		if r['int'] == eth and r['protocol'] == 'C':
			return i
		i += 1
	return False	


def remove_old_connected(eth):
	
	index = old_index(eth)
	if index is not False:
		route_table.pop(index)	
		


def update_static_route(port):
	route = {}
	route = set_route(port)
	print route
	remove_old_connected(route['int'])
	route_table.append(route)


