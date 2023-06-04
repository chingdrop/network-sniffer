from cement import Controller, ex

from scapy_endpoint.controllers.commands.pings import Pings
from scapy_endpoint.controllers.commands.local_network import LocalNetwork
from scapy_endpoint.controllers.commands.scans import Scans


class LANEnumeration(Controller):
    
    class Meta:
        label = 'lan_enumeration'
        stacked_type = 'embedded'
        stacked_on = 'base'

    @ex(
        help='enumerates possible targets on the detected LAN',
        arguments=[
            (['iface'], 
             {'help': 'interface connected to LAN',
              'action': 'store'})
        ],
    )
    def quick_enumeration(self):
        iface = self.app.pargs.iface
        target_list = []
        scans = Scans()
        lan = LocalNetwork().get_network_ip(iface)
        live_hosts = Pings().arp_ping(str(lan))

        for host in live_hosts:
            print(f'\nBeginning port scan for {host["IP"]}!')

            print('\nACK Scan...')
            ack_port = scans.ack_scan(host["IP"])

            print('\nXmas Scan...')
            xmas_open, xmas_filtered = scans.xmas_scan(host["IP"], [i for i in range(1024)])

            print('\nProtocol Scan...')
            open_protos = scans.protocol_scan(host["IP"])

            if ack_port or xmas_open or xmas_filtered or open_protos:
                target_list.append(host)
        
        print('\n'.join(f'{target["IP"]} : {target["MAC"]} could be a potential target' for target in target_list))