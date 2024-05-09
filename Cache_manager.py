import atexit
import os.path
import pickle
import time

from dnslib import QTYPE


class CacheManager:
    CACHE_FILE = 'dns_cache.pkl'

    def __init__(self):
        self.cache = {
            QTYPE.A: {},
            QTYPE.PTR: {},
            QTYPE.NS: {},
            QTYPE.AAAA: {}
        }

        atexit.register(self.save_cache_to_disk)

    def save_cache_to_disk(self):
        with open(self.CACHE_FILE, 'wb') as file:
            pickle.dump(self.cache, file)

    def load_cache_from_disk(self):
        if os.path.exists(self.CACHE_FILE):
            with open(self.CACHE_FILE, 'rb') as file:
                self.cache = pickle.load(file)
                print("Loaded cache from disk")

    def remove_expired_cache(self):
        cur_time = time.time()
        for key, (value, ttl) in self.cache.items():
            if ttl < cur_time:
                del self.cache[key]
