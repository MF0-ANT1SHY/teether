#!/usr/bin/env python3
import json
import time
import os
import csv
import logging
import resource
import sys

from teether.exploit import combined_exploit
from teether.project import Project

logging.basicConfig(level=logging.CRITICAL)

def collectpath(defecttype, time, contract, path):
    filename = f"vul{defecttype}.csv"
    file_exists = os.path.isfile(filename)

    with open(filename, "a", newline="") as csvfile:
        fieldnames = ["time", "contract", "path"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        if not file_exists:
            writer.writeheader()

        writer.writerow(
            {"time": time, "contract": contract, "path": path}
        )

def hex_encode(d):
    return {k: v.hex() if isinstance(v, bytes) else v for k, v in d.items()}


def main(code_path, target_addr, shellcode_addr, amount, savefile=None, initial_storage_file=None, initial_balance=None,
         flags=None):
    savefilebase = savefile or code_path
    if code_path.endswith('.json'):
        with open(code_path, 'rb') as f:
            jd = json.load(f)
        p = Project.from_json(jd)
    else:
        with open(code_path) as infile:
            inbuffer = infile.read().rstrip()
        if inbuffer.startswith("0x"):
            inbuffer = inbuffer[2:]
        name = code_path.rsplit("/", 1)[-1]
        code = bytes.fromhex(inbuffer)
        p = Project(code)
        p.name = name
        with open('%s.project.json' % savefilebase, 'w') as f:
            json.dump(p.to_json(), f)
    amount_check = '+'
    amount = amount.strip()
    print(f"amount is {amount}")
    if amount[0] in ('=', '+', '-'):
        amount_check = amount[0]
        amount = amount[1:]
    amount = int(amount)

    print(p.cfg.testAttri())


if __name__ == '__main__':
    # limit memory to 8GB
    mem_limit = 8 * 1024 * 1024 * 1024
    try:
        rsrc = resource.RLIMIT_VMEM
    except:
        rsrc = resource.RLIMIT_AS
    resource.setrlimit(rsrc, (mem_limit, mem_limit))

    fields = ['code', 'target-address', 'shellcode-address', 'target_amount', 'savefile', 'initial-storage',
              'initial-balance']
    config = {f: None for f in fields}
    config['flags'] = set()

    field_iter = iter(fields)
    for arg in sys.argv[1:]:
        if arg.startswith('--'):
            config['flags'].add(arg[2:].upper())
        else:
            field = next(field_iter)
            config[field] = arg

    if config['target_amount'] is None:
        print('Usage: %s [flags] <code> <target-address> <shellcode-address> <target_amount> [savefile] [initial-storage file] [initial-balance]' % \
              sys.argv[0], file=sys.stderr)
        exit(-1)

    main(config['code'], config['target-address'], config['shellcode-address'], config['target_amount'],
         config['savefile'], config['initial-storage'], config['initial-balance'], config['flags'])
