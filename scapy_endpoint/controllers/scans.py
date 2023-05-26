from cement import Controller, ex
from scapy.all import ARP, Ether, IP, TCP

from scapy_endpoint.my_commands.scan_controller import ScanController


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
        ans, unans = ScanController.layer_3_sr(IP(dst=target)/TCP(dport=(1,1024),flags="A"))

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
        ans, unans = ScanController.layer_3_sr(IP(dst=target)/TCP(dport=(1,1024),flags="FPU"))

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
        ans, unans = ScanController.layer_3_sr(IP(dst=target,proto=(0,255))/"SCAPY")
        
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
        ans, unans = ScanController.layer_2_sr(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target_network))

        ans.summary(lambda s,r: r.sprintf("%Ether.src% - %ARP.psrc%"))