from cement import Controller, ex
from scapy.all import sr1, RandShort, DNS, DNSQR, IP, UDP


class Resolver(Controller):
    class Meta:
        label = 'resolver'
        stacked_type = 'embedded'
        stacked_on = 'base'

    @ex(
        help='resolves an A record',
        arguments=[
            (['target_domain'], 
             {'help': 'target domain name',
              'action': 'store'}),
            (['name_server'], 
             {'help': 'resolving name server',
              'action': 'store'})
        ],
    )
    def resolve_a_record(self):
        domain = self.app.pargs.target_domain
        server = self.app.pargs.name_server
        try:
            ans = sr1(IP(dst=server)/UDP(sport=RandShort(), dport=53)/DNS(rd=1, qd=DNSQR(qname=domain, qtype="A")))
        except Exception as e:
            print(e.message, e.args)

        print(f'{domain} is {ans.an.rdata}.')

    @ex(
        help='resolves an SOA record',
        arguments=[
            (['target_domain'], 
             {'help': 'target domain name',
              'action': 'store'}),
            (['name_server'], 
             {'help': 'resolving name server',
              'action': 'store'})
        ],
    )
    def resolve_soa_record(self):
        domain = self.app.pargs.target_domain
        server = self.app.pargs.name_server
        try:
            ans = sr1(IP(dst=server)/UDP(sport=RandShort(), dport=53)/DNS(rd=1, qd=DNSQR(qname=domain, qtype="SOA")))
        except Exception as e:
            print(e.message, e.args)

        print(f'Primary name server is {ans.an.mname}, contact at {ans.an.rname}')

    @ex(
        help='resolves a MX record',
        arguments=[
            (['target_domain'], 
             {'help': 'target domain name',
              'action': 'store'}),
            (['name_server'], 
             {'help': 'resolving name server',
              'action': 'store'})
        ],
    )
    def resolve_mx_record(self):
        domain = self.app.pargs.target_domain
        server = self.app.pargs.name_server
        try:
            ans = sr1(IP(dst=server)/UDP(sport=RandShort(), dport=53)/DNS(rd=1, qd=DNSQR(qname=domain, qtype="MX")))
        except Exception as e:
            print(e.message, e.args)

        ret = [x.exchange for x in ans.an.iterpayloads()]
        for i in ret:
            print(f'MX {i}')