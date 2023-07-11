from scapy_endpoint.controllers.commands.scans import Scans
from scapy_endpoint.controllers.commands.enums import NON_PRIVILEGED_LOW_PORT, BASIC_PROTOCOLS


class MultiProcTasks:

    def __init__(self) -> None:
        self.scans = Scans()
        self.low_port_range = [i for i in range(1, NON_PRIVILEGED_LOW_PORT)]
        self.proto_range = [i for i in range(1, BASIC_PROTOCOLS)]

    def mp_scan(
            self,
            ip: int,
            ):
        
        ack_unfil, _ = self.scans.ack_scan(ip, self.low_port_range)
        xmas_open, _ = self.scans.xmas_scan(ip, self.low_port_range)
        proto_list = self.scans.protocol_scan(ip, self.proto_range)
        if ack_unfil or xmas_open or proto_list:
            return ip
        else:
            return None