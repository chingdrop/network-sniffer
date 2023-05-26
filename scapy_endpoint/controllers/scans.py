import socket
import fcntl
import struct
from ipaddress import IPv4Address, IPv4Network

from cement import Controller, ex
from scapy.all import sr, srp, ARP, Ether, IP, TCP

from .commands.sr_controller import SRController

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
    return IPv4Address(ip)

def get_local_subnet(self, iface):
    if iface == None:
        iface = 'eth0' or 'wlan0'
    return socket.inet_ntoa(fcntl.ioctl(socket.socket(socket.AF_INET, socket.SOCK_DGRAM), 35099, struct.pack(b'256s', iface.encode()))[20:24])

def get_network_ip(self, iface):
    ip = self.get_local_ip()
    subnet = get_local_subnet(iface)
    network = ip[:ip.rfind('.')+1] + '0'
    return IPv4Network(network + '/' + subnet)

class Scans:

    def ack_scan(self):
        target = self.app.pargs.target_host
        ans, unans = sr(IP(dst=target)/TCP(dport=(1,1024),flags="A"), timeout=5, verbose=0)

        for s,r in ans:
            if s[TCP].dport == r[TCP].sport:
                print(f"Port {s[TCP].dport} is unfiltered.")

    def xmas_scan(self):
        target = self.app.pargs.target_host
        ans, unans = sr(IP(dst=target)/TCP(dport=(1,1024),flags="FPU"), timeout=5, verbose=0)

        for s,r in ans:
            if s[TCP].dport is not None:
                print(f"{s[TCP].dport} is open.")

    def protocol_scan(self):
        target = self.app.pargs.target_host
        ans, unans = sr(IP(dst=target,proto=(0,255))/"SCAPY")
        
        ans.summary(lambda s,r: r.sprintf("%IP.proto% is listening."), timeout=3, verbose=0)
    
    def ip_scan(self):
        target_network = self.app.pargs.target_network
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target_network), timeout=3, verbose=0)

        ans.summary(lambda s,r: r.sprintf("%Ether.src% - %ARP.psrc%"))

class LANEnumeration(Controller):
    
    class Meta:
        label = 'lan_enumeration'
        stacked_type = 'embedded'
        stacked_on = 'base'

    @ex(
        help='starts an ACK scan for ports 1-1024',
        arguments=[
            (['target_host'], 
             {'help': 'target host IP',
              'action': 'store'})
        ],
    )
    def quick_enumeration(self):
