import multiprocessing
import time
from DNSServer import DnsServer
import cmd_test


def run_dns_server():
    dns_server = DnsServer()
    dns_server.start()


if __name__ == "__main__":
    run_dns_server()