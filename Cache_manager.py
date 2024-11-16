import atexit
import os.path
import pickle
import time
import logging

from dnslib import QTYPE


class CacheManager:
    CACHE_FILE = './dns_cache.pkl'

    def __init__(self):
        self.cache = {
            QTYPE.A: {},
            QTYPE.PTR: {},
            QTYPE.NS: {},
            QTYPE.AAAA: {}
        }
        log = logging.getLogger(__name__)
        print(log.name)
        atexit.register(self.save_cache_to_disk)

    def save_cache_to_disk(self):
        with open(self.CACHE_FILE, 'wb') as file:
            pickle.dump(0, file)
        with open(self.CACHE_FILE, 'wb') as file:
            pickle.dump(self.cache, file)
            # print("Cache saved to disk")

    def load_cache_from_disk(self):
        if os.path.exists(self.CACHE_FILE):
            try:
                with open(self.CACHE_FILE, 'rb') as file:
                    self.cache = pickle.load(file)
                    # print("Loaded cache from disk")
            except:
                print("Cache is empty")

    def remove_expired_cache(self):
        cur_time = time.time()
        if len(self.cache.items()) == 0:
            return
        to_del = []
        for key, records in self.cache.items():
            for record, (value, ttl) in records.items():
                if ttl < cur_time:
                    to_del.append((key, record))
        for key, to_del_item in to_del:
            self.cache[key].pop(to_del_item)
            # print(f"Expired cache {to_del_item} has been removed")
