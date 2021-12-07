import time
import socket
import random
import os
from scapy.all import *


def normalScan(ip, numOfPorts, order):
  if order == "inOrder":
    print("Starting port scan")
    if numOfPorts == 65536:
          print("All ports on:"+ip)
    else:
      print("Interesting ports on: "+ip)
    print("PORT\tSTATE\tSERVICE")

    for port in range(numOfPorts):
      s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      s.bind(('', port))
      socket.setdefaulttimeout(1)
      result = s.connect_ex((ip, port))
      if result == 0:
        state = "Open"

        portNum = s.getsockname()[1]

        service = socket.getservbyport(portNum, "tcp")
        print(portNum)
        print(state)
        print(service)

      # create socket and get port #, state, and service
      # List of interesting ports
      # print
  else:
    print("Starting port scan")
    if numOfPorts == 65536:
          print("All ports on:"+ip)
    else:
      print("Interesting ports on: "+ip)
    print("PORT\tSTATE\tSERVICE")
    r = list(range(numOfPorts))
    random.shuffle(r)

    for port in r:
      s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      s.bind(('', port))
      socket.setdefaulttimeout(1)
      result = s.connect_ex((ip, port))
      if result == 0:
        state = "Open"

        portNum = s.getsockname()[1]

        service = socket.getservbyport(portNum, "tcp")
        print(portNum)
        print(state)
        print(service)
    # randomize range(numOfPorts)
    # List of all ports
    # same as above


def tcpSYN(ip, numOfPorts, order):
       # if order==inOrder:
  for i in range(len(numOfPorts)):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # server.connect((target, i))
    server.bind(('', i))  # socket is reachable by any machine
    SYNPacket = IP(dst=ip)/TCP(dport=80, flags="S")
    SYNresponse = sr1(SYNPacket)
    # will output SA or RA  SA = SYnack
    flag = SYNresponse.sprintf('%TCP.flags%')
    if flag == 'SA':
      print("FOUND SYNACK")
      # create RST packet
      RSTpacket = IP(dst=ip)/TCP(dport=80, flags="R")
      send(RSTpacket)
    else:
      print("DID NOT FIND SYNACK")
           # randomize range(numOfPorts)


def tcpFIN(ip, numOfPorts, order):
      # if order==inOrder:
  for i in range(len(numOfPorts)):
      # List of interesting ports
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('', i))
    FINPacket = IP(dst=ip)/TCP(dport=80, flags="F")
    FINresponse = sr1(FINPacket)
    if FINresponse == None:
      print("Port is open")
      send(FINPacket)
    else:
      print("Port is closed")
      sys.exit(1)


def printTable(ip, mode, numOfPorts, order):
  # numOfPorts
  if mode == "normal":
    normalScan(ip, numOfPorts, order)
  elif mode == "syn":
    tcpSYN(ip, numOfPorts, order)
  else:
    tcpFin(ip, numOfPorts, order)


def checkIP(IP):
      # ping -c 1 stop after recieving 1 response from server
  ping = os.system("ping -c 1 " + IP)
  if ping == 0:
    print("IP is alive")
    return True
  else:
    print("IP is dead")
    return False
    sys.exit(1)



def scanIP():
  # 127.0.0.1if checkIP(IP):
  ip="131.229.72.13"
  mode="normal"
  order="dssdfds"
  numOfPorts=100

  start=time.time()
    
  # closedPorts=numOfPorts-len(get_open_ports(ip))
  # print("There are "+closedPorts+" closed ports.")

  printTable(ip, mode, numOfPorts,order)
  end=time.time()

  # print("Finished scanning IP: "+ip+" in "+(end-start)+" seconds.")
  

def main():
  # parameters mode, how many ports, order
  scanIP()

if __name__ == "__main__":
    main()
