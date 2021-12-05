# check if the IP address is alive or not
# resources
# https://explainshell.com/explain?cmd=ping+-c+1+www.orf.at

import os

IP = input("Enter IP address ")
def checkIP(IP):
  ping = os.system("ping -c 1 " + IP) # ping -c 1 stop after recieving 1 response from server
  if ping == 0:
      print("IP is alive")
      continue
      return True
  else:
      print("IP is dead")
      return False
      sys.exit(1)

checkIP(IP)

