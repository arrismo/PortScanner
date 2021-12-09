import time
import socket
import random
import os
from scapy.all import *


# check looping in sending packets
# check if open before sending packets

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

        portNum = s.getsockname()[1] # getting port number
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
    if order == "inOrder":
      print("Starting port scan")
      if numOfPorts == 65536:
          print("All ports on:"+ip)
      else:
        print("Interesting ports on: "+ip)
      print("PORT\tSTATE\tSERVICE")
      for i in range(numOfPorts):
        print(i)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = s.connect_ex((ip, i))
        s.close()
        if result == 0:
          state = "Open"
          portNum = s.getsockname()[1] # getting port number
          service = socket.getservbyport(portNum, "tcp")
          print(portNum)
          print(state)
          print(service)
        while True:
            SYNPacket = IP(dst=ip)/TCP(dport= i, flags="S")
            SYNresponse = sr1(SYNPacket,verbose=False) # will output SA or RA  SA = SYnack
            if SYNresponse is None:
                print("broken")
                break
            else:
                print("working")
                flag = SYNresponse.sprintf('%TCP.flags%')
                if flag == 'SA':
                  print("FOUND SYNACK")
                  # create RST packet
                  RSTpacket = IP(dst=ip)/TCP(dport= i , flags="R")
                  send(RSTpacket,verbose=False,timeout = 2)
    else:
        print("Starting port scan")
        if numOfPorts == 65536:
            print("All ports on:"+ip)
        else:
          print("Interesting ports on: "+ip)
        print("PORT\tSTATE\tSERVICE")

        r = list(range(numOfPorts))
        random.shuffle(r)

        for i in r:
          server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
          #server.bind(('', i))
          socket.setdefaulttimeout(1)
          result = server.connect_ex((ip, i))
          if result == 0:
            state = "Open"

            portNum = server.getsockname()[1] # getting port number
            service = socket.getservbyport(portNum, "tcp")
            print(portNum)
            print(state)
            print(service)
          SYNPacket = IP(dst=ip)/TCP(dport= i, flags="S")
          SYNresponse = sr1(SYNPacket,verbose=0,timeout=2)
          if SYNresponse is None:
              print("broken")
              break
          else:
              print("working")
              flag = SYNresponse.sprintf('%TCP.flags%')
              if flag == 'SA':
                print("FOUND SYNACK")
                # create RST packet
                RSTpacket = IP(dst=ip)/TCP(dport= i , flags="R")
                send(RSTpacket,verbose=False, timeout=2)


def tcpFIN(ip, numOfPorts, order):
    print("Starting port scan")
    if numOfPorts == 65536:
        print("All ports on:"+ip)
    else:
        print("Interesting ports on: "+ip)
    print("PORT\tSTATE\tSERVICE")

    for i in range(numOfPorts):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(('', i))
        socket.setdefaulttimeout(1)
        if result == 0:
          state = "Open"

          portNum = s.getsockname()[1] # getting port number
          service = socket.getservbyport(portNum, "tcp")
          print(portNum)
          print(state)
          print(service)
        FINPacket = IP(dst=ip)/TCP(dport= i , flags="F")
        FINresponse = sr1(FINPacket,verbose=0)
        if FINresponse is None:
            #print("Port is open")
            send(FINPacket,verbose=False)
        else:
            #print("Port is closed")
            sys.exit(1)


def printTable(ip, mode, numOfPorts, order):
  # numOfPorts
  if mode == "normal":
    normalScan(ip, numOfPorts, order)
  elif mode == "SYN":
    tcpSYN(ip, numOfPorts, order)
  else:
    tcpFIN(ip, numOfPorts, order)


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
  ip='131.229.72.13'
  mode="SYN"
  order="inOrder"
  numOfPorts= 500

  start=time.time()

  # closedPorts=numOfPorts-len(get_open_ports(ip))
  # print("There are "+closedPorts+" closed ports.")

  printTable(ip, mode, numOfPorts,order)
  print("done")
  end=time.time()

  # print("Finished scanning IP: "+ip+" in "+(end-start)+" seconds.")


def main():
  # parameters mode, how many ports, order
  scanIP()

if __name__ == "__main__":
    main()
