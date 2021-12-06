# resources
# Arris A7 submisssion
# https://scapy.readthedocs.io/en/latest/introduction.html#quick-demo
# https://readthedocs.org/projects/scapy/downloads/pdf/stable/
# https://docs.python.org/3/howto/sockets.html



import socket
from scapy.all import *

numOfPorts = [50,60,70]

target = "glasgow.smith.edu"
def tcpSYN(numOfPorts):
   #if order==inOrder:
   
   for i in range(len(numOfPorts)):
       server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      # server.connect((target, i))
       server.bind(('', i)) #socket is reachable by any machine
       SYNPacket = IP(dst= target)/TCP(dport= 80,flags="S")
       SYNresponse = sr1(SYNPacket)
       flag = SYNresponse.sprintf('%TCP.flags%') # will output SA or RA  SA = SYnack
       if flag == 'SA':
           print("FOUND SYNACK")
           #create RST packet
           RSTpacket = IP(dst= target)/TCP(dport= 80,flags="R")
           send(RSTpacket)
       else:
           print("DID NOT FIND SYNACK")
           #randomize range(numOfPorts)


        #get port #, state, and service and print

tcpSYN(numOfPorts)