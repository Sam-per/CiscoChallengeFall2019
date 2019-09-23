# Samuel Perreault
# McGill Univ Cisco Night Sept 23 2019

from scapy.layers.inet import TCP, IP
from scapy.sendrecv import sr
from scapy.volatile import RandShort

# Pulled from Scapy documentation, sends a packet to the google.com
firstAns = sr(IP(dst="google.com", ttl = 28), id=RandShort()/TCP(flags=0x2))

# init an array for storing IPs from the trace
IPs = []

# iterates and finds stores all IPs from hops
for rcv in firstAns:
    IPs.append(rcv.src)

# Creates a second request
secAns = sr(IP(dst="yahoo.com", ttl = 28), id=RandShort()/TCP(flags=0x2))

# Checks each IP if it is in first stack trace, and prints it out if it is found
for rcv in secAns:
    if rcv.src in firstAns:
        print(rcv.src)
