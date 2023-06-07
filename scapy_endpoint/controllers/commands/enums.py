from enum import IntEnum


NON_PRIVILEGED_LOW_PORT = 1025
NON_PRIVILEGED_HIGH_PORT = 65534
ICMP_DESTINATION_UNREACHABLE = 3

class TcpFlags(IntEnum):
    SYN_ACK = 0x12
    RST_PSH = 0x14

class IcmpCodes(IntEnum):
    Host_is_unreachable = 1
    Protocol_is_unreachable = 2
    Port_is_unreachable = 3
    Communication_with_destination_network_is_administratively_prohibited = 9
    Communication_with_destination_host_is_administratively_prohibited = 10
    Communication_is_administratively_prohibited = 13