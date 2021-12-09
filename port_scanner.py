import time
import socket
import random
import os
from scapy.all import *



def normalScan(ip, numOfPorts, order):
  if order == "order":
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

def tcpSYN(ip, numOfPorts, order):
    if order == "order":
      print("Starting port scan")
      if numOfPorts == 65536:
          print("All ports on:"+ip)
      else:
        print("Interesting ports on: "+ip)
      print("PORT\tSTATE\tSERVICE")
      for i in range(numOfPorts):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('', i))
        result = s.connect_ex((ip, i))
        SYNresponse = sr1(
        IP(dst=ip)/TCP(dport= i, flags="S"),
        verbose=False, timeout = 1)
        if SYNresponse is None:
            print(i , '\t' , "no response")
        else:
            if result == 0:
              state = "Open"
            portNum = s.getsockname()[1] # getting port number
            service = socket.getservbyport(portNum, "tcp")
            print(portNum ,'\t' , state , '\t' ,  service)
            flag = SYNresponse.sprintf('%TCP.flags%')
            if flag == 'SA':
              RSTpacket = sr(
              IP(dst=ip)/TCP(dport= i , flags="R"), verbose=False,timeout = 1)
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
          server.bind(('', i))
          socket.setdefaulttimeout(1)
          result = server.connect_ex((ip, i))
          if result == 0:
            state = "Open"
            portNum = server.getsockname()[1] # getting port number
            service = socket.getservbyport(portNum, "tcp")
            print(portNum ,'\t' , state , '\t' ,  service)
          SYNresponse = sr1(
          IP(dst=ip)/TCP(dport= i, flags="S"),
          verbose=False, timeout = 1)
          if SYNresponse is None:
              print(i , '\t' , "no response")
          else:
              flag = SYNresponse.sprintf('%TCP.flags%')
              if flag == 'SA':
                RSTpacket = sr(
                IP(dst=ip)/TCP(dport= i , flags="R"), verbose=False,timeout = 1)




def tcpFIN(ip, numOfPorts, order):
    if order == "order":
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
            result = server.connect_ex((ip, i))
            if result == 0:
              state = "Open"
              portNum = server.getsockname()[1] # getting port number
              service = socket.getservbyport(portNum, "tcp")
              print(portNum ,'\t' , state , '\t' ,  service)
            FINresponse = sr1(
            IP(dst=ip)/TCP(dport= i, flags="F"),
            verbose=0, timeout = 1)
            if FINresponse is None:
                print(i , '\t' , "Port is closed")
            else:
                print(i , '\t' , "Port is open")
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
            server.bind(('', i))
            socket.setdefaulttimeout(1)
            result = server.connect_ex((ip, i))
            if result == 0:
              state = "Open"
              portNum = server.getsockname()[1] # getting port number
              service = socket.getservbyport(portNum, "tcp")
              print(portNum ,'\t' , state , '\t' ,  service)
            FINresponse = sr1(
            IP(dst=ip)/TCP(dport= i, flags="F"),
            verbose=0, timeout = 1)
            if FINresponse is None:
                print(i , '\t' , "Port is closed")
            else:
                print(i , '\t' , "Port is open")


def check_open_ports(ip, numOfPorts, order):
    counter=0
    for i in range(numOfPorts):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(('', i))
        socket.setdefaulttimeout(1)
        result = server.connect_ex((ip, i))
        if result == 0:
          state = "Open"
          portNum = server.getsockname()[1] # getting port number
          service = socket.getservbyport(portNum, "tcp")
          counter += 1
    return counter


def printTable(ip, mode, numOfPorts, order):
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


def scanIP(mode,order,numOfPorts):
  ip='131.229.72.13'
  start=time.time()
  closedPorts=numOfPorts-check_open_ports(ip, numOfPorts, order)
  print("There are ", closedPorts ," closed ports.")
  printTable(ip, mode, numOfPorts,order)
  print("done")
  end=time.time()
  print("Finished scanning IP: ",ip," in ",(end-start)," seconds.")


def main(argv):
    mode=sys.argv[1]
    order=sys.argv[2]
    numOfPorts=int(sys.argv[3])

  # parameters mode, how many ports, order
    scanIP(mode,order,numOfPorts)


if __name__ == "__main__":

    main(sys.argv)
