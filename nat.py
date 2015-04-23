# __author__='brcinko'


out_int = ""
in_int = ""
in_networks = []
out_networks = []
nat_en = "none"

def reset_nat():
	global nat_en
	out_int = ""
	in_int = ""
	del in_networks[:]
	del out_networks[:]
	nat_en = "none"




