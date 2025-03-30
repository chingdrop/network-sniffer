from scapy.all import ICMP, IP, TCP

from network_sniffer.enums import (
    TcpFlags,
    IcmpCodes,
    ICMP_DESTINATION_UNREACHABLE,
)
from network_sniffer.packet import BroadcastAdapter, create_tcp_pkt, create_scapy_pkt


bca = BroadcastAdapter()


def ack_scan(target: str, ports: list[int]) -> dict[str, list[int]]:
    results = {
        "closed": [],
        "unfiltered": [],
        "filtered": [],
    }
    pkt = create_tcp_pkt(target, dport=ports, flags="A", seq=12345)
    ans, _ = bca.send(pkt, timeout=5, verbose=0)
    for sent, recv in ans:
        if recv.haslayer(TCP) and recv[TCP].flags == TcpFlags.RST_PSH:
            results["closed"].append(sent[TCP].dport)
        elif (
            recv.haslayer(ICMP)
            and recv[ICMP].type == ICMP_DESTINATION_UNREACHABLE
            and recv[ICMP].code in IcmpCodes
        ):
            results["filtered"].append(sent[TCP].dport)
        else:
            results["unfiltered"].append(sent[TCP].dport)

    return results


def xmas_scan(target: str, ports: list[int]) -> dict[str, list[int]]:
    results = {
        "closed": [],
        "unfiltered": [],
        "open": [],
    }
    pkt = create_tcp_pkt(target, dport=ports, flags="FPU")
    ans, _ = bca.send(pkt, timeout=5, verbose=0)
    for sent, recv in ans:
        if recv.haslayer(TCP) and recv[TCP].flags == TcpFlags.RST_PSH:
            results["closed"].append(sent[TCP].dport)
        elif (
            recv.haslayer(ICMP)
            and recv[ICMP].type == ICMP_DESTINATION_UNREACHABLE
            and recv[ICMP].code in IcmpCodes
        ):
            results["filtered"].append(sent[TCP].dport)
        else:
            results["open"].append(sent[TCP].dport)

    return results


def protocol_scan(target: str, protos: list[int]) -> list[int]:
    pkt = create_scapy_pkt(target, protos)
    ans, _ = bca.send(pkt, timeout=3, verbose=0)
    open_protos = [sent[IP].proto for sent, _ in ans]
    return open_protos
