from cement import Controller, ex
import multiprocessing

from scapy_endpoint.controllers.commands.pings import Pings
from scapy_endpoint.controllers.commands.local_network import LocalNetwork
from scapy_endpoint.controllers.commands.multi_proc import MultiProcTasks as mpt


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
            
        num_processes = (multiprocessing.cpu_count() - 1)
        pool = multiprocessing.Pool(processes=num_processes)
        results = pool.map(mpt.mp_scan, live_hosts)

        pool.close()
        pool.join()

        print()
        for target in results:
            if target:
                print('-' * 65)
                print(f'{target["IP"]} : {target["MAC"]} could be a potential target')
                print(f'{len(target["UnfilteredPorts"])} ports unfiltered by a firewall')
                print(f'{len(target["OpenPorts"])} ports open')
                print(f'{len(target["ListeningProtocols"])} protocols listening')
