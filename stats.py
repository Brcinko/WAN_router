#  __author__ = 'brcinko'

# from core.py import port1,port2


class Stat:
	def __init__(self):
		self.eth0_in = 0
		self.eth0_out = 0
		self.eth1_in = 0
		self.eth1_out = 0


def update_stats(way,iface, s):
	if iface == "eth2":
		if way == "out":
			s.eth0_out += 1
        if iface == "eth2":
                if way == "in":
                        s.eth0_in +=  1
        if iface == "eth3":
                if way == "out":
                        s.eth1_out += 1
        if iface == "eth3":
                if way == "in":
                        s.eth1_in += 1
	return s

def reset_stats():
	eth0_in = 0
	eth0_out = 0
	eth1_in = 0
	eth1_out = 0





