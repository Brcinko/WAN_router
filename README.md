# WAN_router
This is a semestral project. If you are student of FIIT STU dont look at code. Dont even think about it. 

Prerequisites
-------------
 -pyhton 2.7.3
 
 -pip :   
  `apt-get install python-pip`
 
 -scapy:  
  `apt-get install scapy`
 
 -netaddr:  
  `try: pip install netaddr`
 

Ifaces have to be in promisc mode (`ifconfig eth0 promisc`). There maz be problem with interface managing. Try edit `/etc/NetworkManager/NetworkManager.conf` and change variable managed to `managed=true`, then you can edit interface in System Settings.


TODO list
---------

   - ~~statistics (in/out)~~
   
   - ~~sending packets to another interface (try sniff() instead of scket recieveing)~~
   
   - ~~looking on metric~~ 
   
   - ~~RIP logic~~
     - ~~Trigger updates~~
   
   - ~~static NAT~~(maybe), dynamic NAT
   
   - ~~menu(infinity loops), iface as object, starting a stoping threads in menu~~
   
   - PAT(otional)
   
   - Port Forwarding(opt)
