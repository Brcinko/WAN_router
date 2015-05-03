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
	index = []
	for r in route_table:
		for ro in routes:
        		ip = IPNetwork(str(ro['network']) + '/' + str(ro['netmask']))
               		n = ip.prefixlen
                	net = str(ro['network']) + '/' + str(n)
                	# print "Kontrolujem prvu moju ", r['network'], net
                	if r['network'] == net:
                		# print "mam zhodu ", net
				index.append(i)
                i += 1
	# print index
        if index:
		return index
	else:
		return False

def update_route_table(routes, proto):
        # remove old duplicates
	global route_table
	index = find_index(routes)
	if index is not False:
		it = 0
		for i in index:
			# print "mazem ", int(i)
                	route_table.pop(int(i) - it) 
			it += 1
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
	# print eth
	hlpstr = str(eth['IP']) + '/' + str(eth['mask'])
	ip = IPNetwork(hlpstr)
	net = str(ip.network) + '/' + str(ip.prefixlen)
	route = {}
	route.update({'active': True ,'network': net, 'next-hop': str(eth['next-hop']), 'protocol': eth['protocol'], 'metric': str(eth['metric']), 'int': eth['int'], 'eth_IP': eth['IP']})
	
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
		
##################################
# actually update connected route
################################
def update_static_route(port):
	route = {}
	route = set_route(port)
	# print route
	remove_old_connected(route['int'])
	route_table.append(route)

def index_by_net(net):
        i = 0
        for r in route_table:
                if r['network'] == net and r['protocol'] == 'S':
                        return i
                i += 1
        return False


def delete_static_route(net):
	index = index_by_net(net)
	if index is not False:
		route_table.pop(index)
	else:
		print "Error: Bad network address or prefix"

def deactivate_connected_route(iface):
	for r in route_table:
		if r['int'] == iface and r['protocol'] == 'C':
			r['active'] = False

	
