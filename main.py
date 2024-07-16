import multiprocessing
import time
from DNSServer import DnsServer
import cmd_test


def run_dns_server():
    dns_server = DnsServer()
    dns_server.start()


def run_tests():
    cmd_test.main()


if __name__ == "__main__":
    dns_process = multiprocessing.Process(target=run_dns_server)
    dns_process.start()

    time.sleep(5)

    test_process = multiprocessing.Process(target=run_tests)
    test_process.start()

    test_process.join()

