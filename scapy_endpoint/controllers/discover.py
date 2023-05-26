from cement import Controller, ex
from scapy.all import sr, srp, ARP, Ether, IP, ICMP, TCP, UDP


class Ping:

    def arp_ping(self, target):
        host_list = []
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target), timeout=3, verbose=0)
        for s,r in ans:
            host = {
                    "MAC": r[Ether].dst,
                    "IP": r[ARP].psrc
                }
            host_list.append(host)
            
        return host_list
    
    def icmp_ping(self, target):
        host_list = []
        ans, unans = sr(IP(dst=target)/ICMP(), timeout=3, verbose=0)
        for s,r in ans:
            host = {
                    "MAC": r[Ether].dst,
                    "IP": r[IP].dst
                }
            host_list.append(host)
            
        return host_list
    
    def tcp_ping(self, target):
        host_list = []
        ans, unans = sr(IP(dst=target)/TCP(dport=80,flags="S"), timeout=3, verbose=0)
        for s,r in ans:
            host = {
                    "MAC": r[Ether].dst,
                    "IP": r[IP].dst
                }
            host_list.append(host)
            
        return host_list
    
    def udp_ping(self, target):
        host_list = []
        ans, unans = sr(IP(dst=target)/UDP(dport=0), timeout=3, verbose=0)
        for s,r in ans:
            host = {
                    "MAC": r[Ether].dst,
                    "IP": r[IP].dst
                }
            host_list.append(host)
            
        return host_list

class Discover(Controller):
    
    class Meta:
        label = 'discover'
        stacked_type = 'embedded'
        stacked_on = 'base'

    @ex(
        help='starts an ARP ping to discover live hosts',
        arguments=[
            (['iface'], 
             {'help': 'target interface',
              'action': 'store'})
        ],
    )
    def quick_discover(self):
        iface = self.app.pargs.iface
        network_ip = RaspiController.get_network_ip(iface)
        arp_list = Ping.arp_ping(str(network_ip))

    @ex(
        help='starts an ARP ping to discover live hosts',
        arguments=[
            (['iface'], 
             {'help': 'target interface',
              'action': 'store'})
        ],
    )
    def full_discover(self):
        iface = self.app.pargs.iface
        network_ip = RaspiController.get_network_ip(iface)
        arp_list = Ping.arp_ping(str(network_ip))
        icmp_list = Ping.icmp_ping(str(network_ip))
        tcp_list = Ping.tcp_ping(str(network_ip))
        udp_list = Ping.udp_ping(str(network_ip))
