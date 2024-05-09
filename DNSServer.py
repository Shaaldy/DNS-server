import socket
import time

from dnslib import DNSRecord, QTYPE

from Cache_manager import CacheManager

TTL = 10


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
                data, addr = s.recvfrom(1024)
                print(f"Get response from {addr}: {data}")
                dns_request = DNSRecord.parse(data)
                dns_response = dns_res.dns_resolve(dns_request)
                s.sendto(dns_response.pack(), addr)
                print(f"Sending response to {addr}: {dns_response}")


class DNSResolver:
    def __init__(self):
        self.cache_manager = CacheManager()

    def dns_resolve(self, dns_request):
        qtype = dns_request.q.qtype
        key = dns_request.q.qname

        if qtype not in self.cache_manager.cache:
            raise ValueError(f"DNSRequest type {qtype} not supported")

        cache = self.cache_manager.cache[qtype]

        if key in cache and isinstance(cache[key], list) and cache[key]:
            response_record, ttl_end_time = cache[key]
            cache[key] = [response_record, time.time() + TTL]
            return response_record

        response_record = self.send_request_to_server(dns_request)
        if response_record is not None:
            ttl_end_time = time.time() + TTL
            cache[key] = [response_record, ttl_end_time]

        self.decrease_ttl(cache)
        return response_record

    @staticmethod
    def decrease_ttl(cache):
        current_time = time.time()
        for key, (value, ttl_end_time) in list(cache.items()):
            if ttl_end_time < current_time:
                del cache[key]

    @staticmethod
    def send_request_to_server(dns_request):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(15)
                upstream_server = ("8.8.8.8", 53)
                s.sendto(dns_request.pack(), upstream_server)
                data, _ = s.recvfrom(1024)
                return DNSRecord.parse(data)
        except socket.timeout:
            print("Timed out while sending request to upstream server")
            return None


