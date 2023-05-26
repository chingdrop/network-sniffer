from scapy.all import ARP, Ether, IP, ICMP, TCP, UDP

from commands.sr_controller import SRController


class HostDiscovery:

    def arp_ping(self, target):
        host_list = []
        ans, unans = SRController.layer_2_sr(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target))
        for s,r in ans:
            host = {
                    "MAC": r[Ether].dst,
                    "IP": r[ARP].psrc
                }
            host_list.append(host)
            
        return host_list
    
    def icmp_ping(self, target):
        host_list = []
        ans, unans = SRController.layer_3_sr(IP(dst=target)/ICMP())
        for s,r in ans:
            host = {
                    "MAC": r[Ether].dst,
                    "IP": r[IP].dst
                }
            host_list.append(host)
            
        return host_list
    
    def tcp_ping(self, target):
        host_list = []
        ans, unans = SRController.layer_3_sr(IP(dst=target)/TCP(dport=80,flags="S"))
        for s,r in ans:
            host = {
                    "MAC": r[Ether].dst,
                    "IP": r[IP].dst
                }
            host_list.append(host)
            
        return host_list
    
    def udp_ping(self, target):
        host_list = []
        ans, unans = SRController.layer_3_sr(IP(dst=target)/UDP(dport=0))
        for s,r in ans:
            host = {
                    "MAC": r[Ether].dst,
                    "IP": r[IP].dst
                }
            host_list.append(host)
            
        return host_list