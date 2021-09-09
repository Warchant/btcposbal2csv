import unittest
from generate_genesis_block import *


class TestGenerator(unittest.TestCase):
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
