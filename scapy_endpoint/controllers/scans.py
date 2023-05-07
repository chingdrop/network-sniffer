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
    def ACKscan(self):
        ans, unans = sr(IP(dst=self.app.pargs.target_host)/TCP(dport=[80,666],flags="A"))
        for s,r in ans:
            if s[TCP].dport == r[TCP].sport:
               print(f"Port {s[TCP].dport} is unfiltered.")