from celery import shared_task

from network_sniffer.enums import NON_PRIVILEGED_LOW_PORT, BASIC_PROTOCOLS
from network_sniffer.scan import ack_scan, xmas_scan, protocol_scan


@shared_task
def async_vuln_enum(host: dict) -> dict:
    low_port_range = [i for i in range(1, NON_PRIVILEGED_LOW_PORT)]
    proto_range = [i for i in range(1, BASIC_PROTOCOLS)]
    ack_res = ack_scan(host["ip"], low_port_range)
    xmas_res = xmas_scan(host["ip"], low_port_range)
    proto_res = protocol_scan(host["ip"], proto_range)
    host_res = {
        "hostname": host["hostname"],
        "mac": host["mac"],
        "address": host["ip"],
        "unfiltered_ports": ack_res["unfiltered"],
        "open_ports": xmas_res["open"],
        "listening_protocols": proto_res,
    }
    if any(ack_res["unfiltered"], xmas_res["open"], proto_res):
        host_res["vulnerable"] = True
    return host_res


@shared_task
def process_results(results: list[dict]) -> list[dict]:
    return results
