from sys import stdin 

eth0 = {}
eth1 = {}

def menu_eth0():
	print "CONFIG-IF eth0"
	while(True):
                #print "DEBUG second while"
                comm = raw_input('R1(conf-if)#')
                if (comm == "?"):
                       	print "ip add<cr>  then bring up with \"no sh\" "
                if (comm == "no sh"  and  eth0_IP is not NULL):
                        eth0['shtudwon'] = False
                if (comm == "sh"):
                        eth0['shutdown'] = True
                if (comm == "ip add"):
                        print "Set IP (A.B.C.D)"
                        eth0['ip'] = stdin.readline()
                        print "Set mask: "
                        eth0['mask'] = stdin.readline()
                if (comm == "ex" or "exit"):
                        break
	return eth0


def menu_eth1():
	print "CONFIG-IF eth1"
	while(True):
		#print "DEBUG second while"
                comm = raw_input('R1(conf-if)#')
                if (comm == "?"):
                	print "ip add<cr>  then bring up with \"no sh\" "
                if (comm == "no sh"  and  eth0_IP is not NULL):
                        eth1['shutdown'] = False
                if (comm == "sh"):
                        eth1['shutdown'] = True
                if (comm == "ip add"):
                        print "Set IP (A.B.C.D)"
                        eth1['ip'] = stdin.readline()
                        print "Set mask: "
                        eth1['mask'] = stdin.readline()
                if (comm == "ex" or "exit"):
                        break
	return eth1

