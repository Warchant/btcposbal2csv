import unittest
from generate_genesis_block import *


class TestGenerator(unittest.TestCase):
    def test_script_with_prefix(self):
        self.assertEqual('02ff000101', script_with_prefix(0xff).encode().hex())
        self.assertEqual('03ffff000102', script_with_prefix(0xffff).encode().hex())
        self.assertEqual('04ffffff000103', script_with_prefix(0xffffff).encode().hex())
        self.assertEqual('05ffffffff000104', script_with_prefix(0xffffffff).encode().hex())
        self.assertEqual('035634120103', script_with_prefix(0x123456).encode().hex())

    def test_script_in(self):
        nbits = 0x207fffff
        pszTimestamp = "VeriBlock"
        script = script_with_prefix(nbits) + pszTimestamp.encode('ascii')
        expected = "04ffff7f2001040956657269426c6f636b"
        self.assertEqual(expected, script.encode().hex())

    def test_script_out(self):
        expectedScript = "41047c62bbf7f5aa4dd5c16bad99ac621b857fac4e93de86e45f5ada73404eeb44dedcf377b03c14a24e9d51605d9dd2d8ddaef58760d9c4bb82d9c8f06d96e79488ac"
        expectedOut = "00f2052a010000004341047c62bbf7f5aa4dd5c16bad99ac621b857fac4e93de86e45f5ada73404eeb44dedcf377b03c14a24e9d51605d9dd2d8ddaef58760d9c4bb82d9c8f06d96e79488ac"
        initialPubKey = "047c62bbf7f5aa4dd5c16bad99ac621b857fac4e93de86e45f5ada73404eeb44dedcf377b03c14a24e9d51605d9dd2d8ddaef58760d9c4bb82d9c8f06d96e79488"
        scriptPubKey = CScript() + bytes.fromhex(initialPubKey) + OP_CHECKSIG
        self.assertEqual(expectedScript, scriptPubKey.encode().hex())
        reward = 50 * 10 ** 8
        output = CTxOut(scriptPubKey=scriptPubKey, amount=reward)
        self.assertEqual(expectedOut, output.encode().hex())

    def test_tx_id(self):
        expectedId = "fbef9740e790f33f1a1708b3108a7954247491ecc753a63db00d25562935ce74"
        expectedInput = "0000000000000000000000000000000000000000000000000000000000000000ffffffff1104ffff7f2001040956657269426c6f636bffffffff"
        expectedOutput = ""

        initialPubKey = "047c62bbf7f5aa4dd5c16bad99ac621b857fac4e93de86e45f5ada73404eeb44dedcf377b03c14a24e9d51605d9dd2d8ddaef58760d9c4bb82d9c8f06d96e79488"
        pszTimestamp = "VeriBlock"
        nbits = 0x207fffff
        reward = 50 * 10 ** 8

        scriptSig = CScript() + script_with_prefix(nbits) + pszTimestamp.encode('ascii')
        scriptPubKey = CScript() + bytes.fromhex(initialPubKey) + OP_CHECKSIG

        input = CTxIn(scriptSig=scriptSig)
        self.assertEqual(expectedInput, input.encode().hex())

        output = CTxOut(scriptPubKey=scriptPubKey, amount=reward)
        self.assertEqual(expectedOutput, output.encode().hex())

        tx = Tx(
            version=1,
            inputs=[input],
            outputs=[output]
        )

        self.assertEqual(expectedId, tx.tx_id())


if __name__ == '__main__':
    unittest.main()
