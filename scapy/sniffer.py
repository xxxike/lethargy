import argparse
import datetime
from scapy.all import sniff, wrpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.packet import Raw


def format_packet(pkt):
    ts = datetime.datetime.fromtimestamp(float(pkt.time)).strftime("%H:%M:%S.%f")[:-3]
    if pkt.haslayer(IP):
        src = pkt[IP].src
        dst = pkt[IP].dst
        if pkt.haslayer(TCP):
            proto = f"TCP {pkt[TCP].sport}->{pkt[TCP].dport}"
        elif pkt.haslayer(UDP):
            proto = f"UDP {pkt[UDP].sport}->{pkt[UDP].dport}"
        elif pkt.haslayer(ICMP):
            proto = "ICMP"
        else:
            proto = "IP"
    elif pkt.haslayer(ARP):
        src = pkt[ARP].psrc
        dst = pkt[ARP].pdst
        proto = "ARP"
    elif pkt.haslayer(Ether):
        src = pkt[Ether].src
        dst = pkt[Ether].dst
        proto = pkt[Ether].type
    else:
        src = "?"
        dst = "?"
        proto = getattr(pkt, "name", "PKT")
    return f"[{ts}] {src} -> {dst} [{proto}] len={len(pkt)}"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--iface")
    parser.add_argument("-f", "--filter")
    parser.add_argument("-c", "--count", type=int, default=0)
    parser.add_argument("-t", "--timeout", type=float)
    parser.add_argument("-o", "--pcap")
    parser.add_argument("--hex", action="store_true")
    args = parser.parse_args()

    def printer(pkt):
        print(format_packet(pkt))
        if args.hex and pkt.haslayer(Raw):
            print(bytes(pkt[Raw].load).hex())

    pkts = sniff(
        iface=args.iface,
        filter=args.filter,
        prn=printer,
        count=args.count,
        timeout=args.timeout,
        store=bool(args.pcap),
    )

    if args.pcap:
        wrpcap(args.pcap, pkts)


if __name__ == "__main__":
    main()


