import unittest
import string
from _groupsig import ffi

from pygroupsig import groupsig
from pygroupsig import grpkey
from pygroupsig import mgrkey
from pygroupsig import memkey
from pygroupsig import bldkey
from pygroupsig import message
from pygroupsig import signature
from pygroupsig import blindsig
from pygroupsig import constants


UINT_MAX = 2**32 - 1


# Parent class with common functions
class TestCommon(unittest.TestCase):

    # Non-test functions
    def addMember(self):
        msg1 = groupsig.join_mgr(0, self.isskey, self.grpkey)
        msg2 = groupsig.join_mem(1, self.grpkey, msgin = msg1)
        usk = msg2['memkey']
        msg3 = groupsig.join_mgr(2, self.isskey, self.grpkey, msg2['msgout'])
        msg4 = groupsig.join_mem(3, self.grpkey, msgin = msg3, memkey = usk)
        usk = msg4['memkey']
        self.memkeys.append(usk)

    def setUp(self):
        self.code = constants.GL19_CODE
        groupsig.init(self.code, 0)
        group1 = groupsig.setup(self.code)
        grpkey1 = group1['grpkey']
        self.isskey = group1['mgrkey']
        group2 = groupsig.setup(self.code, grpkey1);
        self.cnvkey = group2['mgrkey']
        self.grpkey = group2['grpkey']
        self.memkeys = []

    def tearDown(self):
        groupsig.clear(self.code)


# Tests for group operations
class TestGroupOps(TestCommon):

    # Creates a group
    def test_groupCreate(self):
        self.assertNotEqual(self.grpkey, ffi.NULL)
        self.assertNotEqual(self.cnvkey, ffi.NULL)
        self.assertNotEqual(self.isskey, ffi.NULL)
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
        sig = groupsig.sign("Hello, World!", self.memkeys[0], self.grpkey, UINT_MAX)
        b = groupsig.verify(sig, "Hello, World!", self.grpkey)
        self.assertTrue(b)

    # Rejects a valid signature for a different message, also passed as a string
    def test_rejectValidSignatureWrongMessageString(self):
        self.addMember()
        sig = groupsig.sign("Hello, World!", self.memkeys[0], self.grpkey, UINT_MAX)
        b = groupsig.verify(sig, "Hello, Worlds!", self.grpkey)
        self.assertFalse(b)

    # Accepts a valid signature for a message passed as a byte array
    def test_acceptValidSignatureBytes(self):
        self.addMember()
        sig = groupsig.sign(b"Hello, World!", self.memkeys[0], self.grpkey, UINT_MAX)
        b = groupsig.verify(sig, b"Hello, World!", self.grpkey)
        self.assertTrue(b)

    # Rejects a valid signature for a different message, also passed as a byte array
    def test_rejectValidSignatureWrongMessageBytes(self):
        self.addMember()
        sig = groupsig.sign(b"Hello, World!", self.memkeys[0], self.grpkey, UINT_MAX)
        b = groupsig.verify(sig, b"Hello, Worlds!", self.grpkey)
        self.assertFalse(b)

    # Successfully blind-converts-unblinds two signature by same member
    def test_blindConvertUnblindSameMember(self):
        self.addMember()
        sig1 = groupsig.sign(b"Hello, World1!", self.memkeys[0], self.grpkey, UINT_MAX)
        sig2 = groupsig.sign(b"Hello, World2!", self.memkeys[0], self.grpkey, UINT_MAX)
        b = groupsig.verify(sig1, b"Hello, World1!", self.grpkey)
        self.assertTrue(b)
        b = groupsig.verify(sig2, b"Hello, World2!", self.grpkey)
        self.assertTrue(b)
        bkey = bldkey.bldkey_random(self.code, self.grpkey)
        out = groupsig.blind(self.grpkey, sig1, "Hello, World1!", bkey)
        bsig1 = out["bsig"]
        out = groupsig.blind(self.grpkey, sig2, "Hello, World2!", bkey)
        bsig2 = out["bsig"]
        bkey_pub = bldkey.bldkey_import(self.code,
                                        bldkey.bldkey_export_pub(bkey))
        csigs = groupsig.convert([bsig1, bsig2], self.grpkey, bkey_pub, mgrkey=self.cnvkey)
        nym1 = groupsig.unblind(csigs[0], bkey)
        nym2 = groupsig.unblind(csigs[1], bkey)
        self.assertEqual(nym1['nym'], nym2['nym'])

    # Successfully blind-converts-unblinds two signature by different members
    def test_blindConvertUnblindDifferentMembers(self):
        self.addMember()
        self.addMember()
        sig1 = groupsig.sign(b"Hello, World1!", self.memkeys[0], self.grpkey, UINT_MAX)
        sig2 = groupsig.sign(b"Hello, World2!", self.memkeys[1], self.grpkey, UINT_MAX)
        b = groupsig.verify(sig1, b"Hello, World1!", self.grpkey)
        self.assertTrue(b)
        b = groupsig.verify(sig2, b"Hello, World2!", self.grpkey)
        self.assertTrue(b)
        bkey = bldkey.bldkey_random(self.code, self.grpkey)
        out = groupsig.blind(self.grpkey, sig1, "Hello, World1!", bkey)
        bsig1 = out["bsig"]
        out = groupsig.blind(self.grpkey, sig2, "Hello, World2!", bkey)
        bsig2 = out["bsig"]
        bkey_pub = bldkey.bldkey_import(self.code,
                                        bldkey.bldkey_export_pub(bkey))
        csigs = groupsig.convert([bsig1, bsig2], self.grpkey, bkey_pub, mgrkey=self.cnvkey)
        nym1 = groupsig.unblind(csigs[0], bkey)
        nym2 = groupsig.unblind(csigs[1], bkey)
        self.assertNotEqual(nym1['nym'], nym2['nym'])

    # Non transitivity of conversion
    def test_nonTransitiveConvert(self):
        self.addMember()
        sig1 = groupsig.sign(b"Hello, World1!", self.memkeys[0], self.grpkey, UINT_MAX)
        sig2 = groupsig.sign(b"Hello, World2!", self.memkeys[0], self.grpkey, UINT_MAX)
        b = groupsig.verify(sig1, b"Hello, World1!", self.grpkey)
        self.assertTrue(b)
        b = groupsig.verify(sig2, b"Hello, World2!", self.grpkey)
        self.assertTrue(b)
        bkey = bldkey.bldkey_random(self.code, self.grpkey)
        out = groupsig.blind(self.grpkey, sig1, "Hello, World1!", bkey)
        bsig1 = out["bsig"]
        out = groupsig.blind(self.grpkey, sig2, "Hello, World2!", bkey)
        bsig2 = out["bsig"]
        bkey_pub = bldkey.bldkey_import(self.code,
                                        bldkey.bldkey_export_pub(bkey))
        csigs1 = groupsig.convert([bsig1], self.grpkey, bkey_pub, mgrkey=self.cnvkey)
        csigs2 = groupsig.convert([bsig2], self.grpkey, bkey_pub, mgrkey=self.cnvkey)
        nym1 = groupsig.unblind(csigs1[0], bkey)
        nym2 = groupsig.unblind(csigs2[0], bkey)
        self.assertNotEqual(nym1['nym'], nym2['nym'])


# Tests for message operations
class TestMessageOps(TestCommon):

    def setUp(self):
        self.msg = message.message_from_string("Hello, World!")

    def tearDown(self):
        #message.message_free(self.msg)
        return

    def test_messageExportImport(self):
        b64 = message.message_to_base64(self.msg)
        msg = message.message_from_base64(b64)
        str1 = message.message_to_string(msg)
        str2 = message.message_to_string(self.msg)
        self.assertEqual(str1, str2)

    def test_messageToString(self):
        msg_str = message.message_to_string(self.msg)
        self.assertGreater(len(msg_str), 0)
        self.assertTrue(set(msg_str).issubset(set(string.printable)))


# Tests for signature operations
class TestSignatureOps(TestCommon):

    # Creates a group, adds a member and generates a signature
    def setUp(self):
        super().setUp()
        self.addMember()
        self.sig = groupsig.sign("Hello, World!", self.memkeys[0], self.grpkey, UINT_MAX)

    # Exports and reimports a signature, and it verifies correctly
    def test_sigExportImport(self):
        sig_str = signature.signature_export(self.sig)
        sig = signature.signature_import(self.code, sig_str)
        b = groupsig.verify(sig, "Hello, World!", self.grpkey)
        self.assertTrue(b)

    # Prints a string (this just checks the produced string is not empty)
    def test_sigToString(self):
        sig_str = signature.signature_to_string(self.sig)
        self.assertGreater(len(sig_str), 0)
        self.assertTrue(set(sig_str).issubset(set(string.printable)))


# Tests for blind signature operations
class TestBlindSignatureOps(TestCommon):

    # Creates a group, adds a member and generates a signature
    def setUp(self):
        super().setUp()
        self.addMember()
        self.sig = groupsig.sign("Hello, World!", self.memkeys[0], self.grpkey, UINT_MAX)
        bkey = bldkey.bldkey_random(self.code, self.grpkey)
        out = groupsig.blind(self.grpkey, self.sig, "Hello, World!", bkey)
        self.bsig = out["bsig"]

    # Exports and reimports a signature, and it verifies correctly
    def test_blindsigExportImport(self):
        bsig_str = blindsig.blindsig_export(self.bsig)
        bsig = blindsig.blindsig_import(self.code, bsig_str)
        # This is quite useless, as import returns an exception if the FFI
        # method returns ffi.NULL. Maybe implementing a cmp function for
        # blindsigs  would be good for testing this (and also in general?)
        self.assertIsNot(ffi.NULL, bsig)

    # Prints a string (this just checks the produced string is not empty)
    def test_blindsigToString(self):
        bsig_str = blindsig.blindsig_to_string(self.bsig)
        self.assertGreater(len(bsig_str), 0)
        self.assertTrue(set(bsig_str).issubset(set(string.printable)))


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


# Tests for issuer key operations
class TestIssuerkeyOps(TestCommon):

    # Exports and reimports an issuer key
    def test_isskeyExportImport(self):
        isskey_str = mgrkey.mgrkey_export(self.isskey)
        ikey = mgrkey.mgrkey_import(self.code, isskey_str)
        # This is quite useless, as import returns an exception if the FFI
        # method returns ffi.NULL. Maybe implementing a cmp function for
        # manager keys would be good for testing this (and also in general?)
        self.assertIsNot(ffi.NULL, ikey)


# Tests for converter key operations
class TestConverterkeyOps(TestCommon):

    # Exports and reimports a converter key
    def test_cnvkeyExportImport(self):
        cnvkey_str = mgrkey.mgrkey_export(self.cnvkey)
        ckey = mgrkey.mgrkey_import(self.code, cnvkey_str)
        # This is quite useless, as import returns an exception if the FFI
        # method returns ffi.NULL. Maybe implementing a cmp function for
        # manager keys would be good for testing this (and also in general?)
        self.assertIsNot(ffi.NULL, ckey)


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


# Tests for blinding key operations
class TestBldkeyOps(TestCommon):

    # Creates a group, adds a member and generates a signature
    def setUp(self):
        super().setUp()
        self.bldkey = bldkey.bldkey_random(self.code, self.grpkey)


    # Exports and reimports a blinding key
    def test_bldkeyExportImport(self):
        bldkey_str = bldkey.bldkey_export(self.bldkey)
        bkey = bldkey.bldkey_import(self.code, bldkey_str)
        # This is quite useless, as import returns an exception if the FFI
        # method returns ffi.NULL. Maybe implementing a cmp function for
        # bld keys would be good for testing this (and also in general?)
        self.assertIsNot(ffi.NULL, bkey)

    # Exports and reimports a the public part of a blinding key
    def test_bldkeyExportImportPub(self):
        bldkey_str = bldkey.bldkey_export_pub(self.bldkey)
        bkey = bldkey.bldkey_import(self.code, bldkey_str)
        # This is quite useless, as import returns an exception if the FFI
        # method returns ffi.NULL. Maybe implementing a cmp function for
        # bld keys would be good for testing this (and also in general?)
        self.assertIsNot(ffi.NULL, bkey)


# Define test suites
def suiteGroupOps():
    suiteGroupOps = unittest.TestSuite()
    suiteGroupOps.addTest(TestGroupOps('test_groupCreate'))
    suiteGroupOps.addTest(TestGroupOps('test_addMember'))
    suiteGroupOps.addTest(TestGroupOps('test_acceptValidSignatureString'))
    suiteGroupOps.addTest(TestGroupOps('test_rejectValidSignatureWrongMessageString'))
    suiteGroupOps.addTest(TestGroupOps('test_acceptValidSignatureBytes'))
    suiteGroupOps.addTest(TestGroupOps('test_rejectValidSignatureWrongMessageBytes'))
    suiteGroupOps.addTest(TestGroupOps('test_blindConvertUnblindSameMember'))
    suiteGroupOps.addTest(TestGroupOps('test_blindConvertUnblindDifferentMembers'))
    suiteGroupOps.addTest(TestGroupOps('test_nonTransitiveConvert'))
    return suiteGroupOps


def suiteMsgOps():
    suiteMsgOps = unittest.TestSuite()
    suiteMsgOps.addTest(TestMessageOps('test_messageExportImport'))
    suiteMsgOps.addTest(TestMessageOps('test_messageToString'))
    return suiteMsgOps


def suiteSigOps():
    suiteSigOps = unittest.TestSuite()
    suiteSigOps.addTest(TestSignatureOps('test_sigExportImport'))
    suiteSigOps.addTest(TestSignatureOps('test_sigToString'))
    return suiteSigOps


def suiteBlindsigOps():
    suiteBlindsigOps = unittest.TestSuite()
    suiteBlindsigOps.addTest(TestBlindSignatureOps('test_blindsigExportImport'))
    suiteBlindsigOps.addTest(TestBlindSignatureOps('test_blindsigToString'))
    return suiteBlindsigOps


def suiteGrpkeyOps():
    suiteGrpkeyOps = unittest.TestSuite()
    suiteGrpkeyOps.addTest(TestGrpkeyOps('test_grpkeyExportImport'))
    return suiteGrpkeyOps


def suiteIssuerkeyOps():
    suiteIssuerkeyOps = unittest.TestSuite()
    suiteIssuerkeyOps.addTest(TestIssuerkeyOps('test_isskeyExportImport'))
    return suiteIssuerkeyOps


def suiteConverterkeyOps():
    suiteConverterkeyOps = unittest.TestSuite()
    suiteConverterkeyOps.addTest(TestConverterkeyOps('test_cnvkeyExportImport'))
    return suiteConverterkeyOps


def suiteMemkeyOps():
    suiteMemkeyOps = unittest.TestSuite()
    suiteMemkeyOps.addTest(TestMemkeyOps('test_memkeyExportImport'))
    return suiteMemkeyOps


def suiteBldkeyOps():
    suiteBldkeyOps = unittest.TestSuite()
    suiteBldkeyOps.addTest(TestBldkeyOps('test_bldkeyExportImport'))
    suiteBldkeyOps.addTest(TestBldkeyOps('test_bldkeyExportImportPub'))
    return suiteBldkeyOps


if __name__ == '__main__':
    runner = unittest.TextTestRunner()
    runner.run(suiteGroupOps())
    runner.run(suiteMsgOps())
    runner.run(suiteSigOps())
    runner.run(suiteBlindsigOps())
    runner.run(suiteGrpkeyOps())
    runner.run(suiteIssuerkeyOps())
    runner.run(suiteConverterkeyOps())
    runner.run(suiteMemkeyOps())
    runner.run(suiteBldkeyOps())
