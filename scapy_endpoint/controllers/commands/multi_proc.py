import multiprocessing as mp

from scapy_endpoint.controllers.commands.scans import Scans
from scapy_endpoint.controllers.commands.enums import NON_PRIVILEGED_LOW_PORT, BASIC_PROTOCOLS


class MultiProcTasks:

    def __init__(self) -> None:
        self.scans = Scans()
        self.low_port_range = [i for i in range(1, NON_PRIVILEGED_LOW_PORT)]
        self.proto_range = [i for i in range(1, BASIC_PROTOCOLS)]
        self.num_processes = (mp.cpu_count() - 1)


    def basic_scan_task(self, host: dict) -> dict:
        
        ack_unfil, _ = self.scans.ack_scan(host['IP'], self.low_port_range, verbose=False)
        xmas_open, _ = self.scans.xmas_scan(host['IP'], self.low_port_range, verbose=False)
        proto_list = self.scans.protocol_scan(host['IP'], self.proto_range, verbose=False)
        
        host.update({
            'UnfilteredPorts': ack_unfil,
            'OpenPorts': xmas_open,
            'ListeningProtocols': proto_list
            })
        
        return host
        
    def start_basic_scans(self, hosts):
        pool = mp.Pool(processes=self.num_processes)
        results = pool.map(self.basic_scan_task, hosts)
        pool.close()
        pool.join()
        return results