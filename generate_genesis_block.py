import argparse
import csv
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import List, Union


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def sha256d(b: bytes) -> bytes:
    return sha256(sha256(b))


def sha256t(b: bytes) -> bytes:
    return sha256(sha256d(b))


def encode_int(i, nbytes, encoding='little'):
    """ encode integer i into nbytes bytes using a given byte ordering """
    return i.to_bytes(nbytes, encoding)


def encode_varint(i):
    """ encode a (possibly but rarely large) integer into bytes with a super simple compression scheme """
    if i < 0xfd:
        return bytes([i])
    elif i < 0x10000:
        return b'\xfd' + encode_int(i, 2)
    elif i < 0x100000000:
        return b'\xfe' + encode_int(i, 4)
    elif i < 0x10000000000000000:
        return b'\xff' + encode_int(i, 8)
    else:
        raise ValueError("integer too large: %d" % (i,))


@dataclass
class CScript:
    cmds: List[Union[int, bytes]]

    def encode(self):
        out = []
        for cmd in self.cmds:
            if isinstance(cmd, int):
                # an int is just an opcode, encode as a single byte
                out += [encode_int(cmd, 1)]
            elif isinstance(cmd, bytes):
                # bytes represent an element, encode its length and then content
                length = len(cmd)
                assert length < 75  # any longer than this requires a bit of tedious handling that we'll skip here
                out += [encode_int(length, 1), cmd]

        ret = b''.join(out)
        return encode_varint(len(ret)) + ret


@dataclass
class CTxIn:
    scriptSig: CScript
    nSequence: int = 0
    prevtx: bytes = b'\x00' * 32
    previndex: int = 0

    def encode(self):
        out = []
        out += [self.prevtx[::-1]]  # little endian vs big endian encodings... sigh
        out += [encode_int(self.previndex, 4)]
        out += [self.scriptSig.encode()]
        out += [encode_int(self.nSequence, 4)]
        return b''.join(out)


@dataclass
class CTxOut:
    scriptPubKey: CScript
    amount: int = 0

    def encode(self):
        out = []
        out += [encode_int(self.amount, 8)]
        out += [self.scriptPubKey.encode()]
        return b''.join(out)


@dataclass
class Tx:
    inputs: List[CTxIn]
    outputs: List[CTxOut]
    locktime: int = 0
    version: int = 1

    def encode(self, sig_index=-1) -> bytes:
        """
        Encode this transaction as bytes.
        If sig_index is given then return the modified transaction
        encoding of this tx with respect to the single input index.
        This result then constitutes the "message" that gets signed
        by the aspiring transactor of this input.
        """
        out = []
        # encode metadata
        out += [encode_int(self.version, 4)]
        # encode inputs
        out += [encode_varint(len(self.inputs))]
        # we are just serializing a fully formed transaction
        out += [tx_in.encode() for tx_in in self.inputs]
        assert sig_index == -1, sig_index
        # encode outputs
        out += [encode_varint(len(self.outputs))]
        out += [tx_out.encode() for tx_out in self.outputs]
        # encode... other metadata
        out += [encode_int(self.locktime, 4)]
        out += [encode_int(1, 4) if sig_index != -1 else b'']  # 1 = SIGHASH_ALL
        return b''.join(out)

    def tx_id(self) -> str:
        return sha256(sha256(self.encode()))[::-1].hex()  # little/big endian conventions require byte order swap


@dataclass
class Balance:
    address: str
    satoshi: int

    def to_output(self) -> CTxOut:
        return CTxOut(
            scriptPubKey=CScript([0x0, 0x14, ]),
            amount=self.satoshi
        )


def read_balances(file: Path):
    assert file.exists()
    with open(file, newline='') as csvfile:
        reader = csv.reader(csvfile, delimiter=',')
        for address, satoshis, _ in reader:
            yield Balance(address, satoshis)


def generate_genesis_block(
        nTime: int,
        nNonce: int,
        nBits: int,
        nVersion: int,
        pszTimestamp: str = "VeriBlock",
        balances: List[Balance] = []
):
    # create input
    txin = CTxIn(
        scriptSig=CScript([])
    )

    # create coinbase tx
    tx = Tx(
        version=nVersion,
        inputs=[txin],
        outputs=[]
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--balances", action='store', type=Path, help="Path to csv file with balances")


if __name__ == "__main__":
    main()
