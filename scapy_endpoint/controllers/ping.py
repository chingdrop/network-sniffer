from cement import Controller, ex
from scapy.all import sr, ARP, Ether, IP, ICMP


class Ping(Controller):
    class Meta:
        label = 'ping'
        stacked_type = 'embedded'
        stacked_on = 'base'

    @ex(
        help='starts an ICMP ping',
        arguements=[
            (['target_range'], 
             {'help': 'target IP range',
              'action': 'active ping'})
        ],
    )
    def icmp_ping(self):
        ip_range = self.app.pargs.target_range
        ans, unans = sr(IP(dst=ip_range)/ICMP())
        ans.summary(lambda s,r: r.sprintf("%IP.src% is alive"))

    @ex(
        help='starts an ARP ping',
        arguements=[
            (['target_host'], 
             {'help': 'target host IP',
              'action': 'active ping'})
        ],
    )
    def arp_ping(self):
        target = self.app.pargs.target_host
        ans, unans = sr(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target),timeout=2)
        ans.summary(lambda s,r: r.sprintf("%Ether.src% | %ARP.psrc%"))