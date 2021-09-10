import unittest
from btcutil import *


class TestGenerator(unittest.TestCase):
    def test_decode_nbits(self):
        target = decode_target(0x207fffff)
        self.assertEqual("7fffff0000000000000000000000000000000000000000000000000000000000", target)

    def test_check_pow(self):
        nbits = 0x207fffff
        header = make_header(
            version=1,
            prev_block=b'\x00' * 32,
            merkle_root=bytes.fromhex("fbef9740e790f33f1a1708b3108a7954247491ecc753a63db00d25562935ce74")[::-1],
            timestamp=1337,
            nbits=nbits,
            nonce=0
        )

        self.assertEqual(sha256t(header)[::-1].hex(),
                         "63fb6db8609ea3378e12ff251fa44bee262c77de7e9b25494280ee26d3eebeb1")
        self.assertLess(get_block_hash_int(header), decode_target_int(nbits))

    def test_create_header(self):
        header = make_header(
            version=1,
            prev_block=b'\x00' * 32,
            merkle_root=b'\x11' * 32,
            timestamp=1337,
            nbits=0x207fffff,
            nonce=3
        )

        expected = "010000000000000000000000000000000000000000000000000000000000000000000000111111111111111111111111111111111111111111111111111111111111111139050000ffff7f2003000000"
        self.assertEqual(expected, header.hex())

        header = set_header_nonce(header, 0x01020304)
        expected = "010000000000000000000000000000000000000000000000000000000000000000000000111111111111111111111111111111111111111111111111111111111111111139050000ffff7f2004030201"
        self.assertEqual(expected, header.hex())

        header = set_header_timestamp(header, 0x334455)
        expected = "010000000000000000000000000000000000000000000000000000000000000000000000111111111111111111111111111111111111111111111111111111111111111155443300ffff7f2004030201"
        self.assertEqual(expected, header.hex())

    def test_script_with_prefix(self):
        self.assertEqual('02ff000101', script_with_prefix(0xff).encode().hex())
        self.assertEqual('03ffff000102', script_with_prefix(0xffff).encode().hex())
        self.assertEqual('04ffffff000103', script_with_prefix(0xffffff).encode().hex())
        self.assertEqual('05ffffffff000104', script_with_prefix(0xffffffff).encode().hex())
        self.assertEqual('035634120103', script_with_prefix(0x123456).encode().hex())

    def test_tx_id(self):
        expectedScript = "41047c62bbf7f5aa4dd5c16bad99ac621b857fac4e93de86e45f5ada73404eeb44dedcf377b03c14a24e9d51605d9dd2d8ddaef58760d9c4bb82d9c8f06d96e79488ac"
        expectedOut = "00f2052a010000004341047c62bbf7f5aa4dd5c16bad99ac621b857fac4e93de86e45f5ada73404eeb44dedcf377b03c14a24e9d51605d9dd2d8ddaef58760d9c4bb82d9c8f06d96e79488ac"
        expectedScriptSig = "04ffff7f2001040956657269426c6f636b"

        expectedTx = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff1104ffff7f2001040956657269426c6f636bffffffff0100f2052a010000004341047c62bbf7f5aa4dd5c16bad99ac621b857fac4e93de86e45f5ada73404eeb44dedcf377b03c14a24e9d51605d9dd2d8ddaef58760d9c4bb82d9c8f06d96e79488ac00000000"
        expectedId = "74ce352956250db03da653c7ec91742454798a10b308171a3ff390e74097effb"
        initialPubKey = "047c62bbf7f5aa4dd5c16bad99ac621b857fac4e93de86e45f5ada73404eeb44dedcf377b03c14a24e9d51605d9dd2d8ddaef58760d9c4bb82d9c8f06d96e79488"
        pszTimestamp = "VeriBlock"
        nbits = 0x207fffff
        reward = 50 * 10 ** 8

        scriptSig = CScript() + script_with_prefix(nbits) + pszTimestamp.encode('ascii')
        self.assertEqual(expectedScriptSig, scriptSig.encode().hex())
        scriptPubKey = CScript() + bytes.fromhex(initialPubKey) + OP_CHECKSIG
        self.assertEqual(expectedScript, scriptPubKey.encode().hex())

        input = CTxIn(scriptSig=scriptSig)
        output = CTxOut(scriptPubKey=scriptPubKey, amount=reward)
        self.assertEqual(expectedOut, output.encode().hex())

        tx = Tx(
            version=1,
            inputs=[input],
            outputs=[output]
        )

        self.assertEqual(expectedTx, tx.encode().hex())
        self.assertEqual(expectedId, tx.tx_id())


if __name__ == '__main__':
    unittest.main()
