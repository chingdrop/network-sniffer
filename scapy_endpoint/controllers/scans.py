import socket
import fcntl
import struct
from ipaddress import IPv4Address, IPv4Network

from cement import Controller, ex
from scapy.all import sr, srp, ARP, Ether, hexdump, IP, TCP


class LocalNetwork:

    def get_local_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0)
        try:
            # doesn't have to be reachable
            s.connect(('1.1.1.1', 1))
            ip = s.getsockname()[0]
        except Exception:
            ip = '127.0.0.1'
        finally:
            s.close()
        return ip

    def get_local_subnet(self, iface):
        return socket.inet_ntoa(fcntl.ioctl(socket.socket(socket.AF_INET, socket.SOCK_DGRAM), 35099, struct.pack(b'256s', iface.encode()))[20:24])

    def get_network_ip(self, iface):
        ip = self.get_local_ip()
        subnet = self.get_local_subnet(iface)
        network = ip[:ip.rfind('.')+1] + '0'
        return IPv4Network(network + '/' + subnet)


class Scans:

    def ack_scan(self, target):
        port_list = []
        ans, unans = sr(IP(dst=target)/TCP(dport=(1,1024),flags="A"), timeout=5, verbose=0)

        for s,r in ans:
            if s[TCP].dport == r[TCP].sport:
                port_list.append(s[TCP].dport)
                print(f"Port {s[TCP].dport} is unfiltered.")
        
        return port_list

    def xmas_scan(self, target):
        port_list = []
        ans, unans = sr(IP(dst=target)/TCP(dport=(1,1024),flags="FPU"), timeout=5, verbose=0)

        for s,r in ans:
            if s[TCP].dport is not None:
                port_list.append(s[TCP].dport)
                print(f"{s[TCP].dport} is open.")

        return port_list

    def protocol_scan(self, target):
        ans, unans = sr(IP(dst=target,proto=(0,255))/"SCAPY", timeout=3, verbose=0)
        
        ans.summary(lambda s,r: r.sprintf("%IP.proto% is listening."))
    

class Pings:

    def arp_ping(self, target):
        host_list = []
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target)
        print("Starting an ARP scan with this packet:\n")
        print(pkt.show())
        print(hexdump(pkt))
        print()

        ans, unans = srp(pkt, timeout=3, verbose=0)
        ans.summary(lambda s,r: r.sprintf("%Ether.src% - %ARP.psrc%"))

        for s,r in ans:
            host = {
                    "MAC": r[Ether].dst,
                    "IP": r[ARP].psrc
                }
            host_list.append(host)

        return host_list


class LANEnumeration(Controller):
    
    class Meta:
        label = 'lan_enumeration'
        stacked_type = 'embedded'
        stacked_on = 'base'

    @ex(
        help='poop',
        arguments=[
            (['iface'], 
             {'help': 'interface connected to LAN',
              'action': 'store'})
        ],
    )
    def quick_enumeration(self):
        iface = self.app.pargs.iface
        lan = LocalNetwork().get_network_ip(iface)
        live_hosts = Pings().arp_ping(str(lan))
