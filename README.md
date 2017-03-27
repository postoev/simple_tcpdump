# simple_tcpdump
Console application to extract UDP/IP-datagrams from .pcap file 

# Functions and limitations:
 1. Reject all not UDP/IP packets (e.g, TCP/IP)
 2. Filter UDP-datagrams by IP-address or/and destination port
 3. Doesn't support IPv6

# Usage:
  ### print_pcap [OPTION]... [FILE]  
  **Mandatory argument**: path to .pcap file  
  **Optional arguments**:  
  <pre>
  -a  ADDRESS   print only UDP-datagrams, were sent to address [ADDRESS]  
  -p  PORT      print only UDP-datagrams, were sent to port [PORT]
  </pre>
# Examples:
 **1. Print all UDP-datagrams from file:**  
    ./print_pcap dump.pcap  
 **2. Print only UDP-datagrams, were sent to address 192.168.1.22:**  
    ./print_pcap -a 192.168.1.22 dump.pcap  
 **3. Print only UDP-datagrams, were sent to address 192.168.1.22:9991:**  
    ./print_pcap -a 192.168.1.22 -p 9991 dump.pcap

# Output format:
 [Timestamp] [DstAddress] [DstPort] [PayloadSize]
 
 # Dependencies:
  - cmake (build system), compiler should support C++11
  - libpcap (for .pcap parsing)
