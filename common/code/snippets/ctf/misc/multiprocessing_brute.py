#!/usr/bin/env python3

import hashlib
import itertools
import multiprocessing
from multiprocessing import freeze_support


def brute(worker_function, data_list, processes=8):
    pool = multiprocessing.Pool(processes=processes)
    result = pool.map(worker_function, data_list)
    pool.close()
    return result


def worker(f):
    prefix = "AC34BFB5683"
    for option in itertools.product(map(str, range(10)), repeat=6):
        potential = f + "".join(option)
        if hashlib.sha256(potential).hexdigest().upper().startswith(prefix):
            print("found", potential)
            return


def main():
    brute(worker, map(str, range(10)), processes=6)


if __name__ == "__main__":
    freeze_support()
    main()
