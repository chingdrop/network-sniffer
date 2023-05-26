from timeit import default_timer as timer
from scapy.all import sr, srp


class SRController:

    def __init__(self) -> None:
        pass

    def layer_2_sr(self, pkt):
        try:
            start = timer()
            ans, unans = srp(pkt, timeout=5, verbose=0)
            end = timer()
        except Exception as e:
            print(e)

        delta = end - start
        print(f'Scan took {delta} seconds to complete.')
        return ans, unans

    def layer_3_sr(self, pkt):
        try:
            start = timer()
            ans, unans = sr(pkt, timeout=5, verbose=0)
            end = timer()
        except Exception as e:
            print(e)

        delta = end - start
        print(f'Scan took {delta} seconds to complete.')
        return ans, unans