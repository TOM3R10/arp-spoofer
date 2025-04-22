from tabnanny import verbose

from scapy.all import *
from scapy.layers.inet import IP, Ether
import config

def forward(pkt):
    if pkt.haslayer(IP):
        if pkt[IP].src == config.TARGET_MACHINE_IP:
            pkt[Ether].dst = config.ROUTER_MAC
        elif pkt[IP].dst == config.TARGET_MACHINE_IP:
            pkt[Ether].dst = config.TARGET_MACHINE_MAC
        print(pkt.summary())
        send(pkt, iface="wlp2s0")

sniff(filter="ip", prn=forward, iface="wlp2s0")
