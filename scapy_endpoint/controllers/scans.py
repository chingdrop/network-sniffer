from timeit import default_timer as timer
from cement import Controller, ex
from scapy.all import sr, srp, ARP, Ether, IP, TCP


def sr_handler(pkt):
        try:
            start = timer()
            ans, unans = sr(pkt, timeout=5)
            end = timer()
        except Exception as e:
            print(e)

        delta = end - start
        print(f'Scan took {delta} seconds to complete.')
        return ans, unans

class Scans(Controller):
    class Meta:
        label = 'scans'
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
    def ack_scan(self):
        target = self.app.pargs.target_host
        ans, unans = sr_handler(IP(dst=target)/TCP(dport=(1,1024),flags="A"))

        for s,r in ans:
            if s[TCP].dport == r[TCP].sport:
                print(f"Port {s[TCP].dport} is unfiltered.")

    @ex(
        help='starts an XMAS scan for ports 1-1024',
        arguments=[
            (['target_host'], 
             {'help': 'target host IP',
              'action': 'store'})
        ],
    )
    def xmas_scan(self):
        target = self.app.pargs.target_host
        ans, unans = sr_handler(IP(dst=target)/TCP(dport=(1,1024),flags="FPU"))

        for s,r in ans:
            if s[TCP].dport is not None:
                print(f"{s[TCP].dport} is open.")

    @ex(
        help='starts a protocol scan',
        arguments=[
            (['target_host'], 
             {'help': 'target host IP',
              'action': 'store'})
        ],
    )
    def protocol_scan(self):
        target = self.app.pargs.target_host
        ans, unans = sr_handler(IP(dst=target,proto=(0,255))/"SCAPY")
        
        ans.summary(lambda s,r: r.sprintf("%IP.proto% is listening."))

    @ex(
        help='starts an ip scan',
        arguments=[
            (['target_network'], 
             {'help': 'target network',
              'action': 'store'})
        ],
    )
    def ip_scan(self):
        target_network = self.app.pargs.target_network
        try:
            ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target_network), timeout=3)
        except Exception as e:
            print(e)

        ans.summary(lambda s,r: r.sprintf("%Ether.src% - %ARP.psrc%"))