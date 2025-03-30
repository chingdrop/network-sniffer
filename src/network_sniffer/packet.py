import logging
from typing import List
from scapy.volatile import RandShort
from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import DNS, DNSQR, IP, ICMP, TCP, UDP


def create_arp_pkt(target: str) -> bytes:
    return Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target)


def create_scapy_pkt(target: str, protocols: List[int]) -> bytes:
    return IP(dst=target, proto=protocols) / "SCAPY"


def create_icmp_pkt(target: str) -> bytes:
    return IP(dst=target) / ICMP()


def create_tcp_pkt(target: str, dport: int, flags: str = "S", seq: int = None) -> bytes:
    return IP(dst=target) / TCP(sport=RandShort(), dport=dport, flags=flags, seq=seq)


def create_udp_pkt(target: str, dport: int) -> bytes:
    return IP(dst=target) / UDP(sport=RandShort(), dport=dport)


def create_dns_pkt(target: str, domain: str, qtype: str = "A") -> bytes:
    return (
        IP(dst=target)
        / UDP(sport=RandShort(), dport=53)
        / DNS(rd=1, qd=DNSQR(qname=domain, qtype=qtype))
    )


class BroadcastAdapter:
    def __init__(self, logger) -> None:
        self.logger = logger or logging.getLogger(__name__)
