
def normalScan(ip, numOfPorts, order):
  if order == "inOrder":
    print("Starting port scan")
    print("Interesting ports on:"+ip)
    print("PORT\tSTATE\tSERVICE")
    for port in range(1, numOfPorts):
          s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
          socket.setdefaulttimeout(1)
          result = s.connect_ex((ip, port))
          if numOfPorts == 65536:
            if result == 0:
              portNum = sock.getsockname()
              state = "Open"
              service = socket.getservbyport(portNum, tcp)
              print(portNum+"\t"+state+"\t"+service)

      # create socket and get port #, state, and service
      # List of interesting ports
      # print
  else:
    print("Starting port scan")
    print("All ports on:"+ip)
    print("PORT\tSTATE\tSERVICE")
    r = list(range(portNum))
    random.shuffle(r)
    for port in r:
      s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      socket.setdefaulttimeout(1)
      result = s.connect_ex((ip, port))
      if numOfPorts == 65536:
        if result == 0:
          portNum = sock.getsockname()
          state = "Open"
          service = socket.getservbyport(portNum, tcp)
          print(portNum+"\t"+state+"\t"+service)
    # randomize range(numOfPorts)
    # List of all ports
    # same as above


def tcpSYN(numOfPorts, order):
   if order == inOrder:
    for i in range(numOfPorts):
      # create socket
      # create SYN Packet and send
      if flag == synack:
        # get port #, state, and service and print
      # print
      # create
      # send RST Packet
  else:  
    # randomize range(numOfPorts)
    # same as above   

def tcpFIN(numOfPorts,order):
 
  if order==inOrder:
    for i in range(numOfPorts):
      # List of interesting ports

      # create socket
      # create TCP Packet and send 
      if open: 
        # send packet 
      if closed: 
        # exit 
        # print something 
  else:  
    # randomize range(numOfPorts)
    # List of all interesting ports

    # same as above   


def printTable(mode,numOfPorts,order):
  # numOfPorts
  if normal:
    normalScan(numOfPorts,order)
  elif syn:
    tcpSYN(numOfPorts,order)
  else:
    tcpFin(numOfPorts,order)


def checkIP(IP):
  # check if IP is alive
  return true/false



def scanIP():
  if checkIP(IP):
    
    start=#start time
    closedPorts=numOfPorts-len(get_open_ports(IP))
    print("There are "+closedPorts+" closed ports.")

    printTable(mode, numOfPorts,order)
    end=#end time 
    print("Finished scanning IP: "IP+" in "+(end-start)+" seconds.")
  

def main():
  # parameters mode, how many ports, order
  scanIP()

if __name__ == "__main__":
    main()
