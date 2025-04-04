from celery import chord

from network_sniffer.ping import ping_active_hosts
from network_sniffer.tasks import async_vuln_enum, process_results


def start_vuln_enum(iface: str):
    live_hosts = ping_active_hosts(iface)
    task_group = [async_vuln_enum.s(host) for host in live_hosts]
    callback = process_results.s()
    result = chord(task_group)(callback)
    return result.get()


if __name__ == "__main__":
    start_vuln_enum("Wi-Fi")
