import asyncio
from datetime import datetime

from scapy_endpoint.controllers.commands.scans import Scans
from scapy_endpoint.controllers.commands.enums import NON_PRIVILEGED_LOW_PORT, BASIC_PROTOCOLS


class AsyncTargetEnumeration:

    def __init__(self) -> None:
        self.scans = Scans()
        self.low_port_range = [i for i in range(1, NON_PRIVILEGED_LOW_PORT)]
        self.proto_range = [i for i in range(1, BASIC_PROTOCOLS)]
        self.ack_desc = 'ACK Scan : Testing the firewall rules for detected open ports'
        self.xmas_desc = 'XMAS Scan : Determining if host has any open or filtered ports'
        self.protos_desc = 'Open Protocols : Determining if host has any listening protocols'

    async def coro_scan(
            scan: function, 
            ip: str, 
            desc: str, 
            scan_range: list[int]=[]
            ) -> list[int]:
        
        time = datetime.datetime.now().strftime('%H:%M:%S')
        print(f'\nStarting Scan at {time}...')
        print(desc)
        open_list, _ = scan(ip, scan_range, verbose=False)
        if len(open_list) == 0:
            open_list = []
        return open_list
    
    async def coro_quick_scan(self, host:dict) -> asyncio.coroutine:

        print(f'\nBeginning port scan for {host["IP"]}!')

        return asyncio.gather(
            self.coro_scan(
                scan=self.scans.ack_scan,
                ip=host["IP"],
                desc=self.ack_desc,
                scan_range=self.low_port_range
            ),
            self.coro_scan(
                scan=self.scans.xmas_scan,
                ip=host["IP"],
                desc=self.xmas_desc,
                scan_range=self.low_port_range
            ),
            self.coro_scan(
                scan=self.scans.protocol_scan,
                ip=host["IP"],
                desc=self.protos_desc,
                scan_range=self.proto_range
            )
        )