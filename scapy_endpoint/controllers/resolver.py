from cement import Controller, ex
from scapy import sr1, RandShort, DNS, DNSQR, IP, UDP


class Resolver(Controller):
    class Meta:
        label = 'resolver'
        stacked_type = 'embedded'
        stacked_on = 'base'

    @ex(
        help='resolves an A record',
        arguements=[
            (['target_domain'], 
             {'help': 'target domain name',
              'action': 'name resolve'}),
            (['name_server'], 
             {'help': 'resolving name server',
              'action': 'name server'})
        ],
    )
    def resolve_a_record(self):
        domain = self.app.pargs.target_domain
        server = self.app.pargs.name_server
        ans = sr1(IP(dst=server)/UDP(sport=RandShort(), dport=53)/DNS(rd=1, qd=DNSQR(qname=domain, qtype="A")))
        print(f'{domain} is {ans.an.rdata}.')