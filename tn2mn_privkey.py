#!/usr/bin/env python
import base58
import hashlib
import sys
import requests
import os
import re
import argparse
import random
from requests.auth import HTTPBasicAuth


main = bytes([128])
test = bytes([239])

def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def decodeSecret(key, network):
    assert isinstance(network, bytes), network
    k = base58.b58decode_check(key)
    len_correct = len(k) == 32 + len(network) or (len(k) == 33 + len(network) and k[-1] == 1)
    assert len_correct, "Bad length: {}".format(len(k))
    prefix_ok = k[0:1] == network
    assert prefix_ok, "Bad prefix: {}. Expected {}".format(k[0:1], network)
    is_compressed = len(k) == 33 + len(network)
    return k[len(network):len(network) + 32], is_compressed

def encode_secret(key, network, is_compressed):
    assert isinstance(network, bytes), network
    out = bytearray([])
    out += network
    out += key
    if is_compressed:
        out += bytes([1])
    assert len(out) <= 34, len(out)
    ret = base58.b58encode_check(out)
    return ret

def tn2mn(key):
    data, compressed = decodeSecret(key, test)
    return encode_secret(data, main, compressed)


def process_dump(path):
    assert os.path.exists(path), path + " does not exist"
    with open(path, 'r') as r:
        with open('{}.mainnet'.format(path), 'w') as w:
            for line in r:
                m = re.match('^([a-zA-Z0-9]{52}).*?addr\=([a-zA-Z0-9]{42})', line)
                if m:
                    pk, addr = m.groups()
                    mn = tn2mn(pk).decode('utf-8')
                    yield mn


class BtcApi:
    def __init__(self, apiurl, user, password):
        self.apiurl = apiurl
        self.user = user
        self.password = password

    def req(self, method: str, params=None):
        req = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params if params else [],
            "id": random.randint(0, 2147000000)
        }

        res = requests.post(
            url=self.apiurl,
            auth=HTTPBasicAuth(self.user, self.password),
            json=req
        )

        if res.status_code == 200:
            return res.json()['result']
        else:
            raise Exception(res)


    def rescan(self):
        return self.req('rescan')

    def importprivkey(self, pk, rescan=False):
        return self.req("importprivkey", [pk, "", rescan])

    
parser = argparse.ArgumentParser()
parser.add_argument("--user", type=str, required=True, help="RPC User")
parser.add_argument("--password", type=str, required=True, help="RPC Password")
parser.add_argument("--dumpwallet", type=str, required=True, help="Path to dumpwallet")
args = parser.parse_args()

keys = list(process_dump(args.dumpwallet))

api = BtcApi('http://127.0.0.1:18332', args.user, args.password)
for key in keys:
    print(api.importprivkey(key))

print(api.rescan())
