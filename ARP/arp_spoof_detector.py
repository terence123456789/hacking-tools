import scapy.all as scapy
import argparse
import sys

def get_argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Specify the interface to sniff")
    options = parser.parse_args()

    if not options.interface: #user did not put a value for target
        parser.error("[-] Please specify the interface to sniff. use --help for more info.")

    else:
        return options

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


def sniff(interface):

    # iface: interface to sniff on.
    # store: don't store packets in memory
    # prn: function to call each time a packet is captured
    try:
        scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

    except:
        print("[-] Invalid interface. Please try again")
        sys.exit(0)


def process_sniffed_packet(packet):

    # check if packet has ARP layer
    # check if the ARP packet is type "is at"
    # check that ARP packet does not have source IP as itself. otherwise get_mac function will fail as it cannot obtain its own mac address
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2 and packet[scapy.ARP].psrc != "10.0.2.15":

        real_mac = get_mac(packet[scapy.ARP].psrc) # real mac address of the source IP where the arp packet came from
        response_mac = packet[scapy.ARP].hwsrc # mac address of the source IP in the arp packet

        if real_mac != response_mac:
            print("ARP spoofing attack detected!!!!!!!!!")

options = get_argument()
sniff(options.interface)