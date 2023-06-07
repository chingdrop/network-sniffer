from cement import Controller, ex

from scapy_endpoint.controllers.commands.pings import Pings
from scapy_endpoint.controllers.commands.local_network import LocalNetwork
from scapy_endpoint.controllers.commands.scans import Scans
from scapy_endpoint.controllers.commands.enums import NON_PRIVILEGED_LOW_PORT


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
        lan = LocalNetwork().get_network_ip(iface)
        live_hosts = Pings().arp_ping(str(lan))

        ports = [i for i in range(1, NON_PRIVILEGED_LOW_PORT)]
        target_list = []
        for host in live_hosts:
            print(f'\nBeginning port scan for {host["IP"]}!')

            print('\nACK Scan...')
            print('Testing the firewall rules for detected open ports')
            ack_open, ack_filtered = Scans().ack_scan(host["IP"], ports)

            print('\nXmas Scan...')
            print('Determining if host has any open or filtered ports')
            xmas_open, xmas_filtered = Scans().xmas_scan(host["IP"], ports)
                
            if ack_open or xmas_open:
                target_list.append(host)

            # print('\nProtocol Scan...')
            # open_protos = scans.protocol_scan(host["IP"])
        
        print('\n'.join(f'{target["IP"]} : {target["MAC"]} could be a potential target' for target in target_list))