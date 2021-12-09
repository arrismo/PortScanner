# CSC 251 - Network Security Final Project Port Scanner
# Group Members: Renee Wu and Arris Moise
# References:
# https://explainshell.com/explain?cmd=ping+-c+1+www.orf.at
# Arris A7 submisssion
# https://scapy.readthedocs.io/en/latest/introduction.html#quick-demo
# https://readthedocs.org/projects/scapy/downloads/pdf/stable/
# https://docs.python.org/3/howto/sockets.html
# https://stackoverflow.com/questions/9252373/random-iteration-in-python
# https://stackoverflow.com/questions/7370801/how-to-measure-elapsed-time-in-python
# https://pythontic.com/modules/socket/getservbyport
import time
import socket
import random
import os
from scapy.all import *



def normalScan(ip, numOfPorts, order):
  if order == "order": #check for order of port scanning
    print("Starting port scan")
    if numOfPorts == 65536: #check if all ports
          print("All ports on:"+ip)
    else:
      print("Interesting ports on: "+ip)
    print("PORT\tSTATE\tSERVICE") #print header
    for port in range(numOfPorts): #loop through user defined range of ports
      s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #create socket
      s.bind(('', port))
      socket.setdefaulttimeout(1)
      result = s.connect_ex((ip, port))
      if result == 0: #result returns 0 when port is open
        state = "Open"
        portNum = s.getsockname()[1] #getting port number
        service = socket.getservbyport(portNum, "tcp") #getting service by port
        print(portNum ,'\t' , state , '\t' ,  service)
  else: #repeat above for random scan
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
        print(portNum ,'\t' , state , '\t' ,  service)

def tcpSYN(ip, numOfPorts, order):
    if order == "order":
      print("Starting port scan")
      if numOfPorts == 65536:
          print("All ports on:"+ip)
      else:
        print("Interesting ports on: "+ip)
      print("PORT\tSTATE\tSERVICE")
      for i in range(numOfPorts): # for each port create a socket and bind host and ip
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('', i))
        result = s.connect_ex((ip, i)) # connect ip and each port
        # create and send SYN packet
        SYNresponse = sr1(
        IP(dst=ip)/TCP(dport= i, flags="S"),
        verbose=False, timeout = 1)
        # if no response print print no response
        if SYNresponse is None:
            print(i , '\t' , "no response")
        else:
            if result == 0:  #result returns 0 when port is open
              state = "Open"
            portNum = s.getsockname()[1] # getting port number
            service = socket.getservbyport(portNum, "tcp") # get port service
            print(portNum ,'\t' , state , '\t' ,  service)
            flag = SYNresponse.sprintf('%TCP.flags%') # if response packet has SYN ack flag send RST packet
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
            service = socket.getservbyport(portNum, "tcp") # get port service
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
              # create and send FIN packet
            FINresponse = sr1(
            IP(dst=ip)/TCP(dport= i, flags="F"),
            verbose=0, timeout = 1)
            if FINresponse is None: # if there is no reponse the port is closed if so the port is open
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
    counter=0 #counts how many open ports
    for i in range(numOfPorts):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #create socket
        server.bind(('', i))
        socket.setdefaulttimeout(1)
        result = server.connect_ex((ip, i)) #attempt connection
        if result == 0: #port is open if result returns 0
          portNum = server.getsockname()[1] # getting port number
          counter += 1 #increments by one for each open port
    return counter


def printTable(ip, mode, numOfPorts, order): #checks for what scan mode
  if mode == "normal": #normal scan
    normalScan(ip, numOfPorts, order)
  elif mode == "SYN": #syn scan
    tcpSYN(ip, numOfPorts, order)
  else: #fin scan
    tcpFIN(ip, numOfPorts, order)


def checkIP(IP):
      # ping -c 1 stop after recieving 1 response from server
  ping = os.system("ping -c 1 " + IP)
  if ping == 0:  # if ping is  0 the ip is alive else it is dead
    print("IP is alive")
    return True
  else:
    print("IP is dead")
    return False
    sys.exit(1) # exit program if the ip is dead


def scanIP(mode,order,numOfPorts):
  ip='131.229.72.13' #hardcoded ip address
  start=time.time() #start timer
  closedPorts=numOfPorts-check_open_ports(ip, numOfPorts, order) #check for open ports to calculated closed ports
  print("There are ", closedPorts ," closed ports.")
  printTable(ip, mode, numOfPorts,order) #call printTable
  print("done")
  end=time.time() #end timer
  print("Finished scanning IP: ",ip," in ",(end-start)," seconds.")


def main(argv):
  #set arguments to variables and pass to scanIP()
    mode=sys.argv[1]
    order=sys.argv[2]
    numOfPorts=int(sys.argv[3])

    scanIP(mode,order,numOfPorts)


if __name__ == "__main__":

    main(sys.argv)
