from typing import Tuple
from scapy.layers.inet import ICMP, IP, TCP
from scapy.sendrecv import sr
from scapy.volatile import RandShort
from datetime import datetime as dt

from network_sniffer.commands.enums import (
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
    for sent, rcvd in ans:
        if rcvd.haslayer(TCP) and rcvd[TCP].flags == TcpFlags.RST_PSH:
            results["closed"].append(sent[TCP].dport)
        elif (
            rcvd.haslayer(ICMP)
            and rcvd[ICMP].type == ICMP_DESTINATION_UNREACHABLE
            and rcvd[ICMP].code in IcmpCodes
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
    for sent, rcvd in ans:
        if rcvd.haslayer(TCP) and rcvd[TCP].flags == TcpFlags.RST_PSH:
            results["closed"].append(sent[TCP].dport)
        elif (
            rcvd.haslayer(ICMP)
            and rcvd[ICMP].type == ICMP_DESTINATION_UNREACHABLE
            and rcvd[ICMP].code in IcmpCodes
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
