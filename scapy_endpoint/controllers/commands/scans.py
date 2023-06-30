from typing import Tuple
from scapy.layers.inet import ICMP, IP, TCP
from scapy.sendrecv import sr
from scapy.volatile import RandShort

from scapy_endpoint.controllers.commands.enums import TcpFlags, IcmpCodes, ICMP_DESTINATION_UNREACHABLE


class Scans:

    def __init__(self) -> None:
        self.icmp_codes = [i.value for i in IcmpCodes]

    def ack_scan(self, target, ports, verbose=True) -> Tuple[list, list]:
        src_port = RandShort()
        unfiltered_ports = []
        filtered_ports = []
        closed_ports = []
        try:
            ans, unans = sr(IP(dst=target)/TCP(sport=src_port, dport=ports,flags="A", seq=12345), timeout=5, verbose=0, threaded=True)
            for s,r in ans:
                if r.haslayer(TCP) and r[TCP].flags == TcpFlags.RST_PSH:
                    closed_ports.append(s[TCP].dport)
                elif r.haslayer(ICMP) and \
                    r[ICMP].type == ICMP_DESTINATION_UNREACHABLE and r[ICMP].code in self.icmp_codes:
                    filtered_ports.append(s[TCP].dport)
                else:
                    unfiltered_ports.append(s[TCP].dport)
            
            if verbose:
                if unfiltered_ports:
                    print(f'{len(unfiltered_ports)} ports unfiltered')
                elif filtered_ports:
                    print(f'{len(filtered_ports)} ports filtered')
                else:
                    print('No unfiltered or filtered ports')

            return unfiltered_ports, filtered_ports
        
        except Exception as e:
            print(e)

    def xmas_scan(self, target, ports, verbose=True) -> Tuple[list, list]:
        src_port = RandShort()
        open_ports = []
        filtered_ports = []
        closed_ports = []
        try:
            ans, unans = sr(IP(dst=target)/TCP(sport=src_port, dport=ports, flags="FPU"), timeout=5, verbose=0, threaded=True)
            for s,r in ans:
                if r.haslayer(TCP) and r[TCP].flags == TcpFlags.RST_PSH:
                    closed_ports.append(s[TCP].dport)
                elif r.haslayer(ICMP) and \
                    r[ICMP].type == ICMP_DESTINATION_UNREACHABLE and r[ICMP].code in self.icmp_codes:
                    filtered_ports.append(s[TCP].dport)
                else:
                    open_ports.append(s[TCP].dport)
            
            if verbose:
                if open_ports:
                    print(f'{len(open_ports)} ports open')
                elif filtered_ports:
                    print(f'{len(filtered_ports)} ports filtered')
                else:
                    print('No unfiltered or filtered ports')
            return open_ports, filtered_ports
        
        except Exception as e:
            print(e)

    def protocol_scan(self, target, verbose=True) -> list:
        try:
            ans, unans = sr(IP(dst=target, proto=[i for i in range(256)])/"SCAPY", timeout=3, verbose=0)
            open_protos = [s[IP].proto for s,r in ans]

            if verbose:
                print('\n'.join(f'Protocol {proto} is listening' for proto in open_protos) if open_protos \
                      else "No protocols are listening")
            return open_protos
        
        except Exception as e:
            print(e)