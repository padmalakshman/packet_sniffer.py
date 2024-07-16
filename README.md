@ -0,0 +1,48 @@
import logging
from scapy.all import sniff, IP, TCP, UDP

# Configure logging
logging.basicConfig(filename='packet_log.txt', level=logging.INFO
, format='%(asctime)s - %(message)s')

def packet_callback(packet):
 if IP in packet:
 ip_src = packet[IP].src
 ip_dst = packet[IP].dst
 proto = packet[IP].proto
 
 if proto == 6: # TCP
 protocol = "TCP"
 elif proto == 17: # UDP
 protocol = "UDP"
 else:
 protocol = "Other"
 
 packet_info = f"Source: {ip_src}, Destination: {ip_dst}, Protocol: {protocol}"
 print(packet_info)
 logging.info
(packet_info)
 
 if protocol in ["TCP", "UDP"]:
 payload = bytes(packet[protocol].payload)
 print(f"Payload: {payload}\n")
 logging.info
(f"Payload: {payload}")

def start_sniffing(packet_count, timeout):
 print("Starting packet capture...")
 sniff(prn=packet_callback, store=0, count=packet_count, timeout=timeout)

while True:
 try:
 user_input = input("Press Enter to start packet capture, or type 'exit' to quit: ")
 if user_input.lower() == 'exit':
 print("Exiting...")
 break
 else:
 # Define the number of packets to capture or duration (can be modified as needed)
 packet_count = 50 # Capture 50 packets
 timeout = 30 # Capture for 30 seconds
 start_sniffing(packet_count, timeout)
 except KeyboardInterrupt:
 print("\nPacket capture interrupted by user. Continuing...")
