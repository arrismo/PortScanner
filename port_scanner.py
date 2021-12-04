
def normalScan(numOfPorts,order):
  if order==inOrder:
    for i in range(numOfPorts):
      #create socket and get port #, state, and service
      #List of interesting ports
      #print
  else: 
    #randomize range(numOfPorts)
    #List of all ports
    #same as above   

def tcpSYN(numOfPorts,order):
   if order==inOrder:
    for i in range(numOfPorts):
      #create socket
      #create SYN Packet and send
      if flag == synack:
        #get port #, state, and service and print
      #print
      # create  
      # send RST Packet 
  else:  
    #randomize range(numOfPorts)
    #same as above   

def tcpFIN(numOfPorts,order):
 
  if order==inOrder:
    for i in range(numOfPorts):
      #List of interesting ports

      #create socket
      #create TCP Packet and send 
      if open: 
        # send packet 
      if closed: 
        # exit 
        # print something 
  else:  
    #randomize range(numOfPorts)
    #List of all interesting ports

    #same as above   


def printTable(mode,numOfPorts,order):
  # numOfPorts
  if normal:
    normalScan(numOfPorts,order)
  elif syn:
    tcpSYN(numOfPorts,order)
  else:
    tcpFin(numOfPorts,order)


def checkIP(IP):
  #check if IP is alive
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
  #parameters mode, how many ports, order
  scanIP()

if __name__ == "__main__":
    main()