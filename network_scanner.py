import scapy.all as scapy
import argparse

def get_argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest = "target", help = "Specify the IP or range of IPs to scan")
    options = parser.parse_args()

    if not options.target :
        parser.error("[-] Please specify an IP or a range of IPs, use --help for more info.")

    else:
        return options


# scan an IP or a range of IPs, and returns the scan result in a list of dictionaries
def scan(ip):

    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request

    answered = scapy.srp(arp_request_broadcast, timeout=1) [0]

    client_list = []

    for answer in answered:

        client_dict = {"ip": answer[1].psrc, "mac": answer[1].hwsrc}
        client_list.append(client_dict)

    return client_list


def print_result(results_list):

    print("IP \t\t\t MAC Address\n----------------------------------")

    for client in results_list:
        print(client["ip"] + "\t\t" + " " + client["mac"])


ip_option = get_argument()
scan_result = scan(ip_option.target)
print_result(scan_result)
