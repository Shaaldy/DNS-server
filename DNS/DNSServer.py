import socket
import time
from dnslib import DNSRecord, QTYPE, DNSHeader
from DNS.Cache_manager import CacheManager

TTL = 86_400 # 1 day


def send_empty_response(sock, addr, dns_request):
    header = DNSHeader(id=dns_request.header.id, qr=1, aa=1, ra=1)
    question = dns_request.q
    response = DNSRecord(header, q=question)
    sock.sendto(response.pack(), addr)
    print("No records found. Empty response sent.")


class DnsServer:
    def __init__(self, ip="127.0.0.1", port=53):
        self.ip = ip
        self.port = port

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind((self.ip, self.port))
            print(f"Server started on {self.ip}:{self.port}.")
            dns_res = DNSResolver()
            while True:
                dns_res.check_actual_data()
                data, addr = s.recvfrom(1024)
                dns_request = DNSRecord.parse(data)
                print(f"Received request from {addr} with qtype: {QTYPE[dns_request.q.qtype]} ({dns_request.q.qtype})")
                dns_response = dns_res.dns_resolve(dns_request)
                if dns_response:
                    s.sendto(dns_response.pack(), addr)
                else:
                    send_empty_response(s, addr, dns_request)


class DNSResolver:
    def __init__(self):
        self.cache_manager = CacheManager()
        self.cache_manager.load_cache_from_disk()

    def dns_resolve(self, dns_request):
        qtype = dns_request.q.qtype
        key = dns_request.q.qname

        if qtype not in self.cache_manager.cache:
            raise ValueError(f"DNSRequest type {qtype} not supported")

        cache = self.cache_manager.cache[qtype]

        if key in cache and isinstance(cache[key], list) and cache[key]:
            response_record, ttl_end_time = cache[key]
            cache[key] = [response_record, time.time() + TTL]
            print("Response from cache")
            response_record.header.id = dns_request.header.id
            return response_record

        else:
            response_record = self.send_request_to_server(dns_request)

        if response_record is not None:
            ttl_end_time = time.time() + TTL
            cache[key] = [response_record, ttl_end_time]

        self.decrease_ttl(cache)
        return response_record

    def check_actual_data(self):
        self.cache_manager.remove_expired_cache()
        self.cache_manager.save_cache_to_disk()

    @staticmethod
    def decrease_ttl(cache):
        current_time = time.time()
        for key, (value, ttl_end_time) in list(cache.items()):
            if ttl_end_time < current_time:
                del cache[key]

    @staticmethod
    def send_request_to_server(dns_request):
        def query_server(server):
            try:
                if ':' in server[0]:
                    family = socket.AF_INET6
                else:
                    family = socket.AF_INET
                with socket.socket(family, socket.SOCK_DGRAM) as s:
                    s.settimeout(15)
                    s.sendto(dns_request.pack(), server)
                    data, _ = s.recvfrom(1024)
                    return DNSRecord.parse(data)
            except socket.timeout:
                print(f"Timeout while querying server {server}")
                return None
            except OSError as e:
                print(f"OS error while querying server {server}: {e}")
                return None

        upstream_servers = [
            ("192.5.5.241", 53),  # f.root-servers.net (IPv4)
            ("192.203.230.10", 53),  # e.root-servers.net (IPv4)
            ("192.58.128.30", 53),  # j.root-servers.net (IPv4)
        ]

        for server in upstream_servers:
            response = query_server(server)
            if len(response.ar) == 0:
                continue
            if response:
                break

        if not response:
            print("Timed out while querying all upstream servers")
            return None

        while response and response.header.a == 0:
            authority_section = response.auth
            additional_section = response.ar

            if not authority_section:
                print("No authority section found in the response")
                return None

            next_server = None
            for record in additional_section:
                if record.rtype == QTYPE.A:
                    next_server = str(record.rdata)
                    break

            if not next_server:
                break

            response = query_server((next_server, 53))
            if not response:
                break

        return response
