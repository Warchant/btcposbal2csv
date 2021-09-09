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
class OpCode:
    data: int

    def __int__(self):
        return self.data

OP_PUSHDATA1 = OpCode(0x4c)
OP_PUSHDATA2 = OpCode(0x4d)
OP_PUSHDATA4 = OpCode(0x4e)
OP_1 = OpCode(0x51)
OP_CHECKSIG = OpCode(0xac)


@dataclass
class CScriptNum:
    @staticmethod
    def serialize(n: int) -> bytes:
        if n == 0:
            return bytes()

        result = bytes()
        neg = n < 0
        absval = abs(n)

        while absval:
            result += bytes([absval & 0xff])
            absval >>= 8

        if result[-1] & 0x80:
            result += bytes([0x80 if neg else 0])
        elif neg:
            result[-1] |= 0x80

        return result


@dataclass()
class CScript:
    cmds: bytes = bytes()

    def __add__(self, other):
        if isinstance(other, OpCode):
            assert 0 <= other.data <= 0xff
            self.cmds += bytes([other.data])
            return self

        if isinstance(other, bytes):
            if len(other) < int(OP_PUSHDATA1):
                self.cmds += encode_int(len(other), 1)
            elif len(other) <= 0xff:
                self.cmds += bytes([int(OP_PUSHDATA1)])
                self.cmds += encode_int(len(other), 1)
            elif len(other) <= 0xffff:
                self.cmds += bytes([int(OP_PUSHDATA2)])
                self.cmds += encode_int(len(other), 2)
            else:
                self.cmds += bytes([int(OP_PUSHDATA4)])
                self.cmds += encode_int(len(other), 4)
            self.cmds += other
            return self

        if isinstance(other, int):
            if other == -1 or (1 <= other <= 16):
                self.cmds += bytes([other + (int(OP_1) - 1)])
            elif other == 0:
                self.cmds += bytes([0])
            else:
                return self + CScriptNum.serialize(other)
            return self

        if isinstance(other, CScript):
            self.cmds += other.cmds
            return self

        raise Exception("Bad type: {}".format(other))

    def __iadd__(self, other):
        v = self + other
        self.cmds = v.cmds
        return self

    def encode(self) -> bytes:
        return self.cmds


@dataclass
class CTxIn:
    scriptSig: CScript
    nSequence: int = 0xffffffff
    prevtx: bytes = b'\x00' * 32
    previndex: int = 0xffffffff

    def encode(self):
        out = []
        out += [self.prevtx[::-1]]  # little endian vs big endian encodings... sigh
        out += [encode_int(self.previndex, 4)]

        e = self.scriptSig.encode()
        out += [encode_varint(len(e))]
        out += [e]
        out += [encode_int(self.nSequence, 4)]
        return b''.join(out)


@dataclass
class CTxOut:
    scriptPubKey: CScript
    amount: int = 0xffffffff

    def encode(self):
        out = []
        out += [encode_int(self.amount, 8)]
        e = self.scriptPubKey.encode()
        out += [encode_varint(len(e))]
        out += [e]
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
        return sha256t(self.encode()).hex()


def script_with_prefix(nbits) -> CScript:
    c = CScript() + nbits
    if nbits <= 0xff:
        return c + CScriptNum.serialize(1)
    if nbits <= 0xffff:
        return c + CScriptNum.serialize(2)
    if nbits <= 0xffffff:
        return c + CScriptNum.serialize(3)
    return c + CScriptNum.serialize(4)


def read_balances(file: Path):
    assert file.exists()
    with open(file, newline='') as csvfile:
        reader = csv.reader(csvfile, delimiter=',')
        for script, satoshis, _ in reader:
            try:
                bytes.fromhex(script)
            except:
                raise Exception("Looks like {} is not a script".format(script))
            yield CTxOut(CScript() + script, satoshis)


def generate_genesis_block(
        nTime: int,
        nNonce: int,
        nBits: int,
        nVersion: int,
        pszTimestamp: str = "VeriBlock",
        txouts: List[CTxOut] = []
):
    # create input
    txin = CTxIn(
        scriptSig=CScript(script_with_prefix(nBits)) + [bytes(pszTimestamp)]
    )

    # create coinbase tx
    tx = Tx(
        version=nVersion,
        inputs=[txin],
        outputs=txouts
    )

    merkleroot = tx.tx_id()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--balances", action='store', type=Path, help="Path to csv file with balances")


if __name__ == "__main__":
    main()
