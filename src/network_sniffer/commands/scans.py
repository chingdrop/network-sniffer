from typing import Tuple
from scapy.layers.inet import ICMP, IP, TCP
from scapy.sendrecv import sr
from scapy.volatile import RandShort
from datetime import datetime as dt

from network_sniffer.commands.enums import TcpFlags, IcmpCodes, ICMP_DESTINATION_UNREACHABLE


class Scans:

    def __init__(self) -> None:
        self.icmp_codes = [i.value for i in IcmpCodes]

    def ack_scan(
            self, 
            target: str, 
            ports: list[int], 
            verbose=True
            ) -> Tuple[list, list]:
        
        src_port = RandShort()
        unfiltered_ports = []
        filtered_ports = []
        closed_ports = []
        time = dt.now().strftime('%H:%M:%S')
        pkt = IP(dst=target)/TCP(sport=src_port, dport=ports,flags="A", seq=12345)

        try:
            ans, _ = sr(pkt, timeout=5, verbose=0, threaded=True)
        except Exception as e:
            print(e)

        for s,r in ans:
            if r.haslayer(TCP) and r[TCP].flags == TcpFlags.RST_PSH:
                closed_ports.append(s[TCP].dport)
            elif r.haslayer(ICMP) and \
                r[ICMP].type == ICMP_DESTINATION_UNREACHABLE and r[ICMP].code in self.icmp_codes:
                filtered_ports.append(s[TCP].dport)
            else:
                unfiltered_ports.append(s[TCP].dport)
        
        if verbose:
            print(f'\nACK Scan {target} : Testing the firewall rules for detected open ports')
            print(f'Started : {time}')
            if unfiltered_ports:
                print('\n'.join(f'Port {port} is unfiltered' for port in unfiltered_ports) \
                      if unfiltered_ports else "No ports are filtered")
            elif filtered_ports:
                print('\n'.join(f'Port {port} is filtered' for port in filtered_ports) \
                      if filtered_ports else "No ports are filtered")
            else:
                print('No unfiltered or filtered ports')
        return unfiltered_ports, filtered_ports

    def xmas_scan(
            self, 
            target: str, 
            ports: list[int], 
            verbose=True
            ) -> Tuple[list, list]:
        
        src_port = RandShort()
        open_ports = []
        filtered_ports = []
        closed_ports = []
        time = dt.now().strftime('%H:%M:%S')
        pkt = IP(dst=target)/TCP(sport=src_port, dport=ports, flags="FPU")
        try:
            ans, _ = sr(pkt, timeout=5, verbose=0, threaded=True)
        except Exception as e:
            print(e)

        for s,r in ans:
            if r.haslayer(TCP) and r[TCP].flags == TcpFlags.RST_PSH:
                closed_ports.append(s[TCP].dport)
            elif r.haslayer(ICMP) and \
                r[ICMP].type == ICMP_DESTINATION_UNREACHABLE and r[ICMP].code in self.icmp_codes:
                filtered_ports.append(s[TCP].dport)
            else:
                open_ports.append(s[TCP].dport)
        
        if verbose:
            print(f'\nXMAS Scan {target} : Determining if host has any open or filtered ports')
            print(f'Started : {time}')
            if open_ports:
                print('\n'.join(f'Port {port} is open' for port in open_ports) \
                      if open_ports else "No ports are open")
            elif filtered_ports:
                print('\n'.join(f'Port {port} is filtered' for port in filtered_ports) \
                      if filtered_ports else "No ports are filtered")
            else:
                print('No open or filtered ports')
        return open_ports, filtered_ports

    def protocol_scan(
            self, 
            target: str, 
            protos: list[int],
            verbose=True
            ) -> list[int]:
        
        time = dt.now().strftime('%H:%M:%S')
        pkt = IP(dst=target, proto=protos)/"SCAPY"
        try:
            ans, _ = sr(pkt, timeout=3, verbose=0)
        except Exception as e:
            print(e)

        open_protos = [s[IP].proto for s,r in ans]
        
        if verbose:
            print(f'\nOpen Protocols {target} : Determining if host has any listening protocols')
            print(f'Started : {time}')
            print('\n'.join(f'Protocol {proto} is listening' for proto in open_protos) if open_protos \
                  else "No protocols are listening")
        return open_protos