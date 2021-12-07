import time
import socket
import random

def normalScan(ip, numOfPorts, order):
  if order == "inOrder":
    print("Starting port scan")
    if numOfPorts==65536:
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
    if numOfPorts==65536:
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


#def tcpSYN(numOfPorts, order):
#  if order == inOrder:
    #for i in range(numOfPorts):
      # create socket
      # create SYN Packet and send
     # if flag == synack:
        # get port #, state, and service and print
      # print
      # create
      # send RST Packet
 # else:  
    # randomize range(numOfPorts)
    # same as above   

#def tcpFIN(numOfPorts,order):
 
  #if order==inOrder:
   # for i in range(numOfPorts):
      # List of interesting ports

      # create socket
      # create TCP Packet and send 
     # if open: 
        # send packet 
      #if closed: 
        # exit 
        # print something 
  #  else:  
    # randomize range(numOfPorts)
    # List of all interesting ports

    # same as above   


def printTable(ip,mode,numOfPorts,order):
  # numOfPorts
  if mode=="normal":
    normalScan(ip,numOfPorts,order)
  elif mode=="syn":
    tcpSYN(ip,numOfPorts,order)
  else:
    tcpFin(ip,numOfPorts,order)


def checkIP(IP):
  # check if IP is alive
  return true/false



def scanIP():
  #127.0.0.1if checkIP(IP):
  ip="131.229.72.13"
  mode="normal"
  order="dssdfds"
  numOfPorts=100

  start=time.time()
    
  #closedPorts=numOfPorts-len(get_open_ports(ip))
  #print("There are "+closedPorts+" closed ports.")

  printTable(ip, mode, numOfPorts,order)
  end=time.time()

  #print("Finished scanning IP: "+ip+" in "+(end-start)+" seconds.")
  

def main():
  # parameters mode, how many ports, order
  scanIP()

if __name__ == "__main__":
    main()
