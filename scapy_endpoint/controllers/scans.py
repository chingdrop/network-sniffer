from cement import Controller, ex
from scapy.all import sr, IP, TCP


class Scans(Controller):
    class Meta:
        label = 'scans'
        stacked_type = 'embedded'
        stacked_on = 'base'

    @ex(
        help='starts an ACK scan',
        arguments=[
            (['target_host'], 
             {'help': 'target host IP',
              'action': 'store'})
        ],
    )
    def ack_scan(self):
        target = self.app.pargs.target_host
        try:
            ans, unans = sr(IP(dst=target)/TCP(dport=[80,666],flags="A"), timeout=5)
        except Exception as e:
            print(e.message, e.args)

        for s,r in ans:
            if s[TCP].dport == r[TCP].sport:
                print(f"Port {s[TCP].dport} is unfiltered.")

    @ex(
        help='starts an XMAS scan',
        arguments=[
            (['target_host'], 
             {'help': 'target host IP',
              'action': 'store'})
        ],
    )
    def xmas_scan(self):
        target = self.app.pargs.target_host
        try:
            ans, unans = sr(IP(dst=target)/TCP(dport=666,flags="FPU"), timeout=5)
        except Exception as e:
            print(e.message, e.args)

        for s,r in ans:
            if s[TCP].dport is not None:
                print(f"{s[TCP].dport} is open.")

    @ex(
        help='starts an IP scan',
        arguments=[
            (['target_host'], 
             {'help': 'target host IP',
              'action': 'store'})
        ],
    )
    def ip_scan(self):
        target = self.app.pargs.target_host
        try:
            ans, unans = sr(IP(dst=target,proto=(0,255))/"SCAPY", retry=2, timeout=5)
        except Exception as e:
            print(e.message, e.args)
        
        ans.summary(lambda s,r: r.sprintf("%IP.proto% is listening."))