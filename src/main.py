from network_sniffer.local import get_lan_info
from network_sniffer.ping import ping_active_hosts
from network_sniffer.enums import NON_PRIVILEGED_LOW_PORT, BASIC_PROTOCOLS
from network_sniffer.scan import ack_scan, xmas_scan, protocol_scan


def quick_enumeration(iface: str):
    low_port_range = [i for i in range(1, NON_PRIVILEGED_LOW_PORT)]
    proto_range = [i for i in range(1, BASIC_PROTOCOLS)]
    lan = get_lan_info(iface)
    live_hosts = ping_active_hosts(iface)

    host_results = []
    vuln_hosts = []
    for host in live_hosts:
        ack_res = ack_scan(host["ip"], low_port_range)
        xmas_res = xmas_scan(host["ip"], low_port_range)
        proto_res = protocol_scan(host["ip"], proto_range)
        host_res = {
            "mac": host["mac"],
            "ip": host["ip"],
            "unfiltered_ports": ack_res["unfiltered"],
            "open_ports": xmas_res["open"],
            "listening_protocols": proto_res,
        }
        host_results.append(host_res)
        if any(ack_res["unfiltered"], xmas_res["open"], proto_res):
            vuln_hosts.append(host_res)

    print(f"\nQuick Enumeration Results for Network: {lan["network"]}")
    print(f"Total Hosts Found: {len(live_hosts)}")
    print(f"Total Vulnerable Hosts: {len(vuln_hosts)}\n")
    return host_results, vuln_hosts


if __name__ == "__main__":
    quick_enumeration("Wi-Fi")