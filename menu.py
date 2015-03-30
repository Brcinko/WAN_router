from sys import stdin 

eth0 = {}
eth1 = {}

def menu_eth0():
	print "CONFIG-IF eth0"
	while(True):
                print "DEBUG second while"
                comm = stdin.readline()
                if (comm == "?\n"):
                       	print "ip add<cr>  then bring up with \"no sh\" "
                if (comm == "no sh\n"  and  eth0_IP is not NULL):
                        eth0['shtudwon'] = False
                if (comm == "sh\n"):
                        eth0['shutdown'] = True
                if (comm == "ip add\n"):
                        print "Set IP (A.B.C.D)"
                        eth0['ip'] = stdin.readline()
                        print "Set mask: "
                        eth0['mask'] = stdin.readline()
                if (comm == "ex\n" or "exit\n"):
                        break
	return eth0


def menu_eth1():
	print "CONFIG-IF eth1"
	while(True):
		print "DEBUG second while"
                comm = stdin.readline()
                if (comm == "?\n"):
                	print "ip add<cr>  then bring up with \"no sh\" "
                if (comm == "no sh\n"  and  eth0_IP is not NULL):
                        eth1['shutdown'] = False
                if (comm == "sh\n"):
                        eth1['shutdown'] = True
                if (comm == "ip add\n"):
                        print "Set IP (A.B.C.D)"
                        eth1['ip'] = stdin.readline()
                        print "Set mask: "
                        eth1['mask'] = stdin.readline()
                if (comm == "ex\n" or "exit\n"):
                        break
	return eth1

