from scapy_endpoint.controllers.commands.scans import Scans
from scapy_endpoint.controllers.commands.enums import NON_PRIVILEGED_LOW_PORT, BASIC_PROTOCOLS


class MultiProcTasks:

    @staticmethod
    def mp_scan(host: int):
        scans = Scans()
        low_port_range = [i for i in range(1, NON_PRIVILEGED_LOW_PORT)]
        proto_range = [i for i in range(1, BASIC_PROTOCOLS)]
        ack_unfil, _ = scans.ack_scan(host['IP'], low_port_range)
        xmas_open, _ = scans.xmas_scan(host['IP'], low_port_range)
        proto_list = scans.protocol_scan(host['IP'], proto_range)
        
        if ack_unfil or xmas_open or proto_list:
            return host
        else:
            return None