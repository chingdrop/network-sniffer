import logging
from typing import List
from scapy.all import (
    sr,
    srp,
    RandShort,
    ARP,
    DNS,
    DNSQR,
    Ether,
    IP,
    ICMP,
    TCP,
    UDP,
    ICMP,
    IP,
    Packet,
    TCP,
    UDP,
    Scapy_Exception,
)
import socket


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


def create_dns_pkt(target: str, domain: str, qtype: str) -> bytes:
    return (
        IP(dst=target)
        / UDP(sport=RandShort(), dport=53)
        / DNS(rd=1, qd=DNSQR(qname=domain, qtype=qtype))
    )


class BroadcastAdapter:
    def __init__(self, logger=None) -> None:
        self.logger = logger or logging.getLogger(__name__)

    def _send_rcv(
        self,
        level: str,
        packet: bytes,
        timeout: int = 3,
        verbose: int = 0,
        retry: int = 0,
        threaded: bool = True,
    ):
        try:
            if level == "ip":
                return sr(
                    packet,
                    timeout=timeout,
                    verbose=verbose,
                    retry=retry,
                    threaded=threaded,
                )
            elif level == "eth":
                return srp(
                    packet,
                    timeout=timeout,
                    verbose=verbose,
                    retry=retry,
                    threaded=threaded,
                )
            else:
                self.logger.error(
                    f"Invalid level '{level}' specified, use 'ip' or 'eth'"
                )
                return None
        except Scapy_Exception as e:
            self.logger.error(f"Scapy error occurred: {e}")
        except OSError as e:
            self.logger.error(f"OS error occurred: {e}")
        except socket.error as e:
            self.logger.error(f"Socket error occurred: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error: {e}")

    def send(
        self,
        packet: bytes,
        timeout: int = 3,
        verbose: int = 0,
        retry: int = 0,
        threaded: bool = True,
    ) -> List[tuple]:
        return self._send_rcv(
            level="ip",
            packet=packet,
            timeout=timeout,
            verbose=verbose,
            retry=retry,
            threaded=threaded,
        )

    def send1(
        self,
        packet: bytes,
        timeout: int = 3,
        verbose: int = 0,
        retry: int = 0,
        threaded: bool = True,
    ) -> Packet:
        ans, _ = self.send(
            packet=packet,
            timeout=timeout,
            verbose=verbose,
            retry=retry,
            threaded=threaded,
        )
        if ans:
            return ans[0][1]
        return None

    def sendp(
        self,
        packet: bytes,
        timeout: int = 3,
        verbose: int = 0,
        retry: int = 0,
        threaded: bool = True,
    ) -> List[tuple]:
        return self._send_rcv(
            level="eth",
            packet=packet,
            timeout=timeout,
            verbose=verbose,
            retry=retry,
            threaded=threaded,
        )

    def sendp1(
        self,
        packet: bytes,
        timeout: int = 3,
        verbose: int = 0,
        retry: int = 0,
        threaded: bool = True,
    ) -> Packet:
        ans, _ = self.sendp(
            packet=packet,
            timeout=timeout,
            verbose=verbose,
            retry=retry,
            threaded=threaded,
        )
        if ans:
            return ans[0][1]
        return None
