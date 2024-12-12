import unittest
import string
from _groupsig import ffi

from pygroupsig import groupsig
from pygroupsig import grpkey
from pygroupsig import mgrkey
from pygroupsig import memkey
from pygroupsig import signature
from pygroupsig import constants


UINT_MAX = 2**32 - 1


# Parent class with common functions
class TestCommon(unittest.TestCase):

    # Non-test functions
    def addMember(self):
        msg1 = groupsig.join_mgr(0, self.mgrkey, self.grpkey)
        msg2 = groupsig.join_mem(1, self.grpkey, msgin = msg1)
        usk = msg2['memkey']
        msg3 = groupsig.join_mgr(2, self.mgrkey, self.grpkey, msg2['msgout'])
        msg4 = groupsig.join_mem(3, self.grpkey, msgin = msg3, memkey = usk)
        usk = msg4['memkey']
        self.memkeys.append(usk)

    def setUp(self):
        self.code = constants.DL21SEQ_CODE
        groupsig.init(self.code, 0)
        group = groupsig.setup(self.code)
        self.mgrkey = group['mgrkey']
        self.grpkey = group['grpkey']
        self.memkeys = []

    def tearDown(self):
        groupsig.clear(self.code)


# Tests for group operations
class TestGroupOps(TestCommon):

    # Creates a group
    def test_groupCreate(self):
        self.assertNotEqual(self.grpkey, ffi.NULL)
        self.assertNotEqual(self.mgrkey, ffi.NULL)
        self.assertEqual(groupsig.get_joinseq(self.code), 3)
        self.assertEqual(groupsig.get_joinstart(self.code), 0)

    # Adds one member
    def test_addMember(self):
        n_members = len(self.memkeys)
        self.addMember()
        self.assertEqual(len(self.memkeys), n_members+1)
        self.assertNotEqual(self.memkeys[n_members], ffi.NULL)

    # Accepts a valid signature for a message passed as a string
    def test_acceptValidSignatureString(self):
        self.addMember()
        sig = groupsig.sign("{ \"scope\": \"scp\", \"message\": \"Hello, World!\" }", self.memkeys[0], self.grpkey, UINT_MAX)
        b = groupsig.verify(sig, "{ \"scope\": \"scp\", \"message\": \"Hello, World!\" }", self.grpkey)
        self.assertTrue(b)

    # Rejects a valid signature for a different message, also passed as a string
    def test_rejectValidSignatureWrongMessageString(self):
        self.addMember()
        sig = groupsig.sign("{ \"scope\": \"scp\", \"message\": \"Hello, World!\" }", self.memkeys[0], self.grpkey, UINT_MAX)
        b = groupsig.verify(sig, "{ \"scope\": \"scp\", \"message\": \"Hello, Worlds!\" }", self.grpkey)
        self.assertFalse(b)

    # Accepts a valid signature for a message passed as a byte array
    def test_acceptValidSignatureBytes(self):
        self.addMember()
        sig = groupsig.sign(b"{ \"scope\": \"scp\", \"message\": \"Hello, World!\" }", self.memkeys[0], self.grpkey, UINT_MAX)
        b = groupsig.verify(sig, b"{ \"scope\": \"scp\", \"message\": \"Hello, World!\" }", self.grpkey)
        self.assertTrue(b)

    # Rejects a valid signature for a different message, also passed as a byte array
    def test_rejectValidSignatureWrongMessageBytes(self):
        self.addMember()
        sig = groupsig.sign(b"{ \"scope\": \"scp\", \"message\": \"Hello, World!\" }", self.memkeys[0], self.grpkey, UINT_MAX)
        b = groupsig.verify(sig, b"{ \"scope\": \"scp\", \"message\": \"Hello, Worlds!\" }", self.grpkey)
        self.assertFalse(b)

    # Successfully links 2 signatures by the same user
    def test_linkSignaturesSameUser(self):
        self.addMember()
        msg = b"{ \"scope\": \"scp\", \"message\": \"Hello, World!\" }"
        sig1 = groupsig.sign(msg, self.memkeys[0], self.grpkey, 1)
        sig2 = groupsig.sign(msg, self.memkeys[0], self.grpkey, 2)
        sigs = [sig1, sig2]
        msgs = [msg, msg]
        gslink = groupsig.link(self.memkeys[0], self.grpkey, msg, sigs, msgs)
        proof = gslink['proof']
        b = groupsig.verify_link(proof, self.grpkey, msg, sigs, msgs)
        self.assertTrue(b)

    # Fails to link 2 signatures by different user
    def test_linkSignaturesDifferentUser(self):
        self.addMember()
        self.addMember()
        msg = b"{ \"scope\": \"scp\", \"message\": \"Hello, World!\" }"
        sig1 = groupsig.sign(msg, self.memkeys[0], self.grpkey, 1)
        sig2 = groupsig.sign(msg, self.memkeys[1], self.grpkey, 2)
        sigs = [sig1, sig2]
        msgs = [msg, msg]
        gslink = groupsig.link(self.memkeys[0], self.grpkey, msg, sigs, msgs)
        proof = gslink['proof']
        self.assertIsNone(proof)

    # Rejects seqlink proof by same user but with wrong order (swap)
    def test_linkSignaturesSameUserWrongOrderSwap(self):
        self.addMember()
        msg = b"{ \"scope\": \"scp\", \"message\": \"Hello, World!\" }"
        sig1 = groupsig.sign(msg, self.memkeys[0], self.grpkey, 1)
        sig2 = groupsig.sign(msg, self.memkeys[0], self.grpkey, 2)
        sigs = [sig2, sig1]
        msgs = [msg, msg]
        gslink = groupsig.seqlink(self.memkeys[0], self.grpkey, msg, sigs, msgs)
        proof = gslink['proof']
        b = groupsig.verify_seqlink(proof, self.grpkey, msg, sigs, msgs)
        self.assertFalse(b)

    # Rejects seqlink proof by same user but with wrong order (skip)
    def test_linkSignaturesSameUserWrongOrderSkip(self):
        self.addMember()
        msg = b"{ \"scope\": \"scp\", \"message\": \"Hello, World!\" }"
        sig1 = groupsig.sign(msg, self.memkeys[0], self.grpkey, 1)
        _ = groupsig.sign(msg, self.memkeys[0], self.grpkey, 2)
        sig3 = groupsig.sign(msg, self.memkeys[0], self.grpkey, 3)
        sigs = [sig1, sig3]
        msgs = [msg, msg]
        gslink = groupsig.seqlink(self.memkeys[0], self.grpkey, msg, sigs, msgs)
        proof = gslink['proof']
        b = groupsig.verify_seqlink(proof, self.grpkey, msg, sigs, msgs)
        self.assertFalse(b)


# Tests for signature operations
class TestSignatureOps(TestCommon):

    # Creates a group, adds a member and generates a signature
    def setUp(self):
        super().setUp()
        self.addMember()
        self.sig = groupsig.sign("{ \"scope\": \"scp\", \"message\": \"Hello, World!\" }", self.memkeys[0], self.grpkey, UINT_MAX)

    # Exports and reimports a signature, and it verifies correctly
    def test_sigExportImport(self):
        sig_str = signature.signature_export(self.sig)
        sig = signature.signature_import(self.code, sig_str)
        b = groupsig.verify(sig, "{ \"scope\": \"scp\", \"message\": \"Hello, World!\" }", self.grpkey)
        self.assertTrue(b)

    # Prints a string (this just checks the produced string is not empty)
    def test_sigToString(self):
        sig_str = signature.signature_to_string(self.sig)
        self.assertGreater(len(sig_str), 0)
        self.assertTrue(set(sig_str).issubset(set(string.printable)))


# Tests for group key operations
class TestGrpkeyOps(TestCommon):

    # Exports and reimports a group key
    def test_grpkeyExportImport(self):
        grpkey_str = grpkey.grpkey_export(self.grpkey)
        gpk = grpkey.grpkey_import(self.code, grpkey_str)
        # This is quite useless, as import returns an exception if the FFI
        # method returns ffi.NULL. Maybe implementing a cmp function for
        # grp keys would be good for testing this (and also in general?)
        self.assertIsNot(ffi.NULL, gpk)


# Tests for manager key operations
class TestManagerkeyOps(TestCommon):

    # Exports and reimports an manager key
    def test_mgrkeyExportImport(self):
        mgrkey_str = mgrkey.mgrkey_export(self.mgrkey)
        ikey = mgrkey.mgrkey_import(self.code, mgrkey_str)
        # This is quite useless, as import returns an exception if the FFI
        # method returns ffi.NULL. Maybe implementing a cmp function for
        # manager keys would be good for testing this (and also in general?)
        self.assertIsNot(ffi.NULL, ikey)


# Tests for member key operations
class TestMemkeyOps(TestCommon):

    # Exports and reimports a member key
    def test_memkeyExportImport(self):
        self.addMember()
        memkey_str = memkey.memkey_export(self.memkeys[0])
        mkey = memkey.memkey_import(self.code, memkey_str)
        # This is quite useless, as import returns an exception if the FFI
        # method returns ffi.NULL. Maybe implementing a cmp function for
        # mem keys would be good for testing this (and also in general?)
        self.assertIsNot(ffi.NULL, mkey)


# Define test suites
def suiteGroupOps():
    suiteGroupOps = unittest.TestSuite()
    suiteGroupOps.addTest(TestGroupOps('test_groupCreate'))
    suiteGroupOps.addTest(TestGroupOps('test_addMember'))
    suiteGroupOps.addTest(TestGroupOps('test_acceptValidSignatureString'))
    suiteGroupOps.addTest(TestGroupOps('test_rejectValidSignatureWrongMessageString'))
    suiteGroupOps.addTest(TestGroupOps('test_acceptValidSignatureBytes'))
    suiteGroupOps.addTest(TestGroupOps('test_rejectValidSignatureWrongMessageBytes'))
    suiteGroupOps.addTest(TestGroupOps('test_linkSignaturesSameUser'))
    suiteGroupOps.addTest(TestGroupOps('test_linkSignaturesDifferentUser'))
    suiteGroupOps.addTest(TestGroupOps('test_linkSignaturesSameUserWrongOrderSwap'))
    suiteGroupOps.addTest(TestGroupOps('test_linkSignaturesSameUserWrongOrderSkip'))
    return suiteGroupOps


def suiteSigOps():
    suiteSigOps = unittest.TestSuite()
    suiteSigOps.addTest(TestSignatureOps('test_sigExportImport'))
    suiteSigOps.addTest(TestSignatureOps('test_sigToString'))
    return suiteSigOps


def suiteGrpkeyOps():
    suiteGrpkeyOps = unittest.TestSuite()
    suiteGrpkeyOps.addTest(TestGrpkeyOps('test_grpkeyExportImport'))
    return suiteGrpkeyOps


def suiteManagerkeyOps():
    suiteManagerkeyOps = unittest.TestSuite()
    suiteManagerkeyOps.addTest(TestManagerkeyOps('test_mgrkeyExportImport'))
    return suiteManagerkeyOps


def suiteMemkeyOps():
    suiteMemkeyOps = unittest.TestSuite()
    suiteMemkeyOps.addTest(TestMemkeyOps('test_memkeyExportImport'))
    return suiteMemkeyOps


if __name__ == '__main__':
    runner = unittest.TextTestRunner()
    runner.run(suiteGroupOps())
    runner.run(suiteSigOps())
    runner.run(suiteGrpkeyOps())
    runner.run(suiteManagerkeyOps())
    runner.run(suiteMemkeyOps())
