import unittest
from generate_genesis_block import *


class TestGenerator(unittest.TestCase):
    def test_script_with_prefix(self):
        self.assertEqual('02ff000101', script_with_prefix(0xff).encode().hex())
        self.assertEqual('03ffff000102', script_with_prefix(0xffff).encode().hex())
        self.assertEqual('04ffffff000103', script_with_prefix(0xffffff).encode().hex())
        self.assertEqual('05ffffffff000104', script_with_prefix(0xffffffff).encode().hex())
        self.assertEqual('035634120103', script_with_prefix(0x123456).encode().hex())


if __name__ == '__main__':
    unittest.main()
