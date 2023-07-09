from cement import Controller, ex
import asyncio

from scapy_endpoint.controllers.commands.pings import Pings
from scapy_endpoint.controllers.commands.local_network import LocalNetwork
from scapy_endpoint.controllers.commands.coro import AsyncTargetEnumeration


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
        async_enum = AsyncTargetEnumeration()
        iface = self.app.pargs.iface
        lan = LocalNetwork().get_network_ip(iface)
        live_hosts = Pings().arp_ping(str(lan))
        
        async def start_host_enum(hosts):
            target_list = []
            for host in hosts:
                results = await async_enum.coro_quick_scan(host)
                if results:
                    target_list.append(host)
                return target_list
                
        target_list = asyncio.run(start_host_enum(live_hosts))
        print('\n'.join(f'{target["IP"]} : {target["MAC"]} could be a potential target' for target in target_list))