#!/usr/share/python3

import scapy.all as scapy
import optparse

# This is a ARP Spoof detection program

def get_mac(ip):                           # Function to get MAC Address of the device of given IP 
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:fff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/scapy_packet
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

def get_arguements():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", help="To specify the interface of the network", dest=interface)
    (options, arguements) = parser.parse_args()
    if not options.interface:
        parser.error("[-] Please specify the interface of the network")
    return options

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def process_sniffed_packet(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.TCP].op == 2:
        try:
            real_mac = get_mac(packet[scapy.ARP].psrc)
            response_mac = packet[scapy.ARP].hwsrc

            if real_mac != response_mac:
                print("[!] ARP Spoofing detected! You are under attack!")
        except IndexError:
            pass

options = get_arguements()
interface = options.interface
sniff(interface)
