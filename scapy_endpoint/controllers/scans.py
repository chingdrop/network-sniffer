from cement import Controller, ex
from scapy import sr, IP, TCP


class Scans(Controller):
    class Meta:
        label = 'scans'
        stacked_type = 'embedded'
        stacked_on = 'base'

    @ex(
        help='starts an ACK scan',
        arguements=[
            (['target_host'], 
             {'help': 'target host IP',
              'action': 'active scan'})
        ],
    )
    def ack_scan(self):
        target = self.app.pargs.target_host
        ans, unans = sr(IP(dst=target)/TCP(dport=[80,666],flags="A"))
        for s,r in ans:
            if s[TCP].dport == r[TCP].sport:
               print(f"Port {s[TCP].dport} is unfiltered.")

    @ex(
        help='starts an XMAS scan',
        arguements=[
            (['target_host'], 
             {'help': 'target host IP',
              'action': 'active scan'})
        ],
    )
    def xmas_scan(self):
        target = self.app.pargs.target_host
        ans, unans = sr(IP(dst=target)/TCP(dport=666,flags="FPU"))
        for s,r in ans:
            if s[TCP].dport is not None:
                 print(f"{s[TCP].dport} is open.")

    @ex(
        help='starts an IP scan',
        arguements=[
            (['target_range'], 
             {'help': 'target IP range',
              'action': 'active scan'})
        ],
    )
    def ip_scan(self):
        target = self.app.pargs.target_host
        ans, unans = sr(IP(dst=target,proto=(0,255))/"SCAPY",retry=2)
        ans.summary(lambda s,r: r.sprintf("%IP.proto% is listening."))