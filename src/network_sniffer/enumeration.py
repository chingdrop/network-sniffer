from network_sniffer.commands.pings import Pings
from network_sniffer.commands.local_network import LocalNetwork
from network_sniffer.commands.multi_proc import MultiProcTasks


class LANEnumeration:

    def quick_enumeration(self, iface):
        lan = LocalNetwork().get_network_ip(iface)
        live_hosts = Pings().arp_ping(str(lan))
        mpt = MultiProcTasks()

        results = mpt.start_basic_scans(live_hosts)

        print()
        for target in results:
            print("-" * 65)
            if (
                target["UnfilteredPorts"]
                or target["OpenPorts"]
                or target["ListeningProtocols"]
            ):
                print(f'{target["IP"]} : {target["MAC"]} could be a potential target')
                print(
                    f'{len(target["UnfilteredPorts"])} ports unfiltered by a firewall'
                )
                print(f'{len(target["OpenPorts"])} ports open')
                print(f'{len(target["ListeningProtocols"])} protocols listening')
            else:
                print(f'{target["IP"]} : {target["MAC"]} is secure')
                print("No firewall rules affecting this host")
                print("No open ports")
                print("No protocols listening")
