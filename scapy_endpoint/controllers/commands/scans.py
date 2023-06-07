from scapy.layers.inet import ICMP, IP, TCP
from scapy.sendrecv import sr
from scapy.volatile import RandShort


class Scans:

    def ack_scan(self, target, ports, verbose=True):
        src_port = RandShort()
        try:
            ans, unans = sr(IP(dst=target)/TCP(sport=src_port, dport=ports,flags="A", seq=12345), timeout=5, verbose=0)
            unfiltered_ports = [s[TCP].dport for s,r in ans if r.haslayer(TCP) and r[TCP].flags == 0x14]
            filtered_ports = [s[TCP].dport for s,r in ans if r.haslayer(ICMP) and \
                              r[ICMP].type == 3 and r[ICMP].code in [1, 2, 3, 9, 10, 13]]

            if verbose:
                message = '\n'.join(f'Port {port} is open' for port in unfiltered_ports) if unfiltered_ports \
                    else '\n'.join(f'Port {port} is filtered' for port in filtered_ports) if filtered_ports \
                    else 'No open or filtered ports'
                print(message)
            return unfiltered_ports, filtered_ports
        
        except Exception as e:
            print(e)

    def xmas_scan(self, target, ports, verbose=True):
        src_port = RandShort()
        try:
            ans, unans = sr(IP(dst=target)/TCP(sport=src_port, dport=ports, flags="FPU"), timeout=5, verbose=0)
            open_ports = [s[TCP].dport for s,r in ans if r.haslayer(TCP) and r[TCP].flags == 0x14]
            filtered_ports = [s[TCP].dport for s,r in ans if r.haslayer(ICMP) and \
                              r[ICMP].type == 3 and r[ICMP].code in [1, 2, 3, 9, 10, 13]]
            
            if verbose:
                message = '\n'.join(f'Port {port} is open' for port in open_ports) if open_ports \
                    else '\n'.join(f'Port {port} is filtered' for port in filtered_ports) if filtered_ports \
                    else 'No open or filtered ports'
                print(message)
            return open_ports, filtered_ports
        
        except Exception as e:
            print(e)

    def protocol_scan(self, target, verbose=True):
        try:
            ans, unans = sr(IP(dst=target, proto=[i for i in range(256)])/"SCAPY", timeout=3, verbose=0)
            open_protos = [s[IP].proto for s,r in ans]

            if verbose:
                print('\n'.join(f'Protocol {proto} is listening' for proto in open_protos) if open_protos \
                      else "No protocols are listening")
            return open_protos
        
        except Exception as e:
            print(e)