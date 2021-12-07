# resources
# Arris A7 submisssion
# https://scapy.readthedocs.io/en/latest/introduction.html#quick-demo
# https://readthedocs.org/projects/scapy/downloads/pdf/stable/
# https://docs.python.org/3/howto/sockets.html

import socket
from scapy.all import *
target = "glasgow.smith.edu"

numOfPorts = [50,60,70]
def tcpFIN(numOfPorts):
  #if order==inOrder:
    for i in range(len(numOfPorts)):
      #List of interesting ports
       server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
       server.bind(('', i))
       FINPacket = IP(dst= target)/TCP(dport= 80,flags="F")
       FINresponse = sr1(FINPacket)
       if FINresponse == None:
           print("Port is open")
           send(FINPacket)
       else:
           print("Port is closed")
           sys.exit(1)

  # else:
    #randomize range(numOfPorts)
    #List of all interesting ports

tcpFIN(numOfPorts)