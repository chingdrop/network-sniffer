from cement import Controller, ex
from scapy.all import sr, ARP, Ether, IP, ICMP


class Discover(Controller):
    class Meta:
        label = 'discover'
        stacked_type = 'embedded'
        stacked_on = 'base'

    @ex(
        help='starts an ICMP ping',
        arguments=[
            (['target_range'], 
             {'help': 'target IP range',
              'action': 'store'})
        ],
    )
    def icmp_ping(self):
        ip_range = self.app.pargs.target_range
        try:
            ans, unans = sr(IP(dst=ip_range)/ICMP())
        except Exception as e:
            print(e.message, e.args)

        ans.summary(lambda s,r: r.sprintf("%IP.src% is alive"))

    @ex(
        help='starts an ARP ping',
        arguments=[
            (['target_host'], 
             {'help': 'target host IP',
              'action': 'store'})
        ],
    )
    def arp_ping(self):
        target = self.app.pargs.target_host
        try:
            ans, unans = sr(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target),timeout=2)
        except Exception as e:
            print(e.message, e.args)
            
        ans.summary(lambda s,r: r.sprintf("%Ether.src% | %ARP.psrc%"))