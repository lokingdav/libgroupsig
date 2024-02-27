# file "libgroupsig_build.py"

import path

from pygroupsig.common_build import ffibuilder

import pygroupsig.grp_key_build
import pygroupsig.mgr_key_build
import pygroupsig.mem_key_build
import pygroupsig.bld_key_build
import pygroupsig.message_build
import pygroupsig.signature_build
import pygroupsig.blindsig_build
import pygroupsig.proof_build
import pygroupsig.identity_build
import pygroupsig.trapdoor_build
import pygroupsig.gml_build
import pygroupsig.crl_build
import pygroupsig.groupsig_build

# Schemes
import pygroupsig.gl19_build
import pygroupsig.bbs04_build
import pygroupsig.ps16_build
import pygroupsig.klap20_build
import pygroupsig.kty04_build
import pygroupsig.cpy06_build
#import pygroupsig.dl21_build
#import pygroupsig.dl21seq_build

groupsigcdef = r"""
int groupsig_hello_world(void);

uint8_t groupsig_is_supported_scheme(uint8_t code);

const groupsig_t* groupsig_get_groupsig_from_str(char *str);

const groupsig_t* groupsig_get_groupsig_from_code(uint8_t code);

int groupsig_init(uint8_t code, unsigned int seed);

int groupsig_clear(uint8_t code);

int groupsig_setup(uint8_t code, groupsig_key_t *grpkey, groupsig_key_t *mgrkey,
gml_t *gml);

int groupsig_get_joinseq(uint8_t code, uint8_t *seq);

int groupsig_get_joinstart(uint8_t code, uint8_t *start);

int groupsig_join_mem(message_t **mout, groupsig_key_t *memkey,
int seq, message_t *min, groupsig_key_t *grpkey);

int groupsig_join_mgr(message_t **mout, gml_t *gml, groupsig_key_t *mgrkey,
int seq, message_t *min, groupsig_key_t *grpkey);

int groupsig_sign(groupsig_signature_t *sig, message_t *msg,
groupsig_key_t *memkey,
groupsig_key_t *grpkey, unsigned int seed);

int groupsig_verify(uint8_t *ok, groupsig_signature_t *sig, message_t *msg,
groupsig_key_t *grpkey);

int groupsig_verify_batch(
uint8_t *ok,
groupsig_signature_t **sigs,
message_t **msgs,
uint32_t n,
groupsig_key_t *grpkey);

int groupsig_open(uint64_t *index,
groupsig_proof_t *proof,
crl_t *crl,
groupsig_signature_t *sig,
groupsig_key_t *grpkey,
groupsig_key_t *mgrkey,
gml_t *gml);

int groupsig_open_verify(uint8_t *ok,
groupsig_proof_t *proof,
groupsig_signature_t *sig,
groupsig_key_t *grpkey);

int groupsig_blind(groupsig_blindsig_t *bsig, groupsig_key_t **bldkey,
groupsig_key_t *grpkey, groupsig_signature_t *sig,
message_t *msg);

int groupsig_convert(groupsig_blindsig_t **csig,
groupsig_blindsig_t **bsig, uint32_t n_bsigs,
groupsig_key_t *grpkey, groupsig_key_t *mgrkey,
groupsig_key_t *bldkey, message_t *msg);

int groupsig_unblind(identity_t *nym, groupsig_signature_t *sig,
groupsig_blindsig_t *bsig,
groupsig_key_t *grpkey, groupsig_key_t *bldkey,
message_t *msg);

int groupsig_reveal(trapdoor_t *trap,
crl_t *crl,
gml_t *gml,
uint64_t index);

int groupsig_trace(uint8_t *ok,
groupsig_signature_t *sig,
groupsig_key_t *grpkey,
crl_t *crl,
groupsig_key_t *mgrkey,
gml_t *gml);

int groupsig_claim(groupsig_proof_t *proof,
groupsig_key_t *memkey,
groupsig_key_t *grpkey,
groupsig_signature_t *sig);


int groupsig_claim_verify(uint8_t *ok,
groupsig_proof_t *proof,
groupsig_signature_t *sig,
groupsig_key_t *grpkey);

int groupsig_prove_equality(groupsig_proof_t *proof,
groupsig_key_t *memkey,
groupsig_key_t *grpkey,
groupsig_signature_t **sigs,
uint16_t n_sigs);

int groupsig_prove_equality_verify(uint8_t *ok,
groupsig_proof_t *proof,
groupsig_key_t *grpkey,
groupsig_signature_t **sigs,
uint16_t n_sigs);

int groupsig_identify(uint8_t *ok,
groupsig_proof_t **proof,
groupsig_key_t *grpkey,
groupsig_key_t *memkey,
groupsig_signature_t *sig,
message_t *msg);

int groupsig_link(groupsig_proof_t **proof,
groupsig_key_t *grpkey,
groupsig_key_t *memkey,
message_t *msg,
groupsig_signature_t **sigs,
message_t **msgs,
uint32_t n);

int groupsig_verify_link(uint8_t *ok,
groupsig_key_t *grpkey,
groupsig_proof_t *proof,
message_t *msg,
groupsig_signature_t **sigs,
message_t **msgs,
uint32_t n);

int groupsig_seqlink(groupsig_proof_t **proof,
groupsig_key_t *grpkey,
groupsig_key_t *memkey,
message_t *msg,
groupsig_signature_t **sigs,
message_t **msgs,
uint32_t n);

int groupsig_verify_seqlink(uint8_t *ok,
groupsig_key_t *grpkey,
groupsig_proof_t *proof,
message_t *msg,
groupsig_signature_t **sigs,
message_t **msgs,
uint32_t n);

int groupsig_get_code_from_str(uint8_t *code, char *name);
"""

ffibuilder.cdef("""
void free(void *);
""")

ffibuilder.cdef(groupsigcdef)

c_header_file = path.Path("../../../src/include/groupsig.h").abspath()
c_include_path = path.Path("../../../src/include").abspath()
c_lib_path =  path.Path("../../../build/lib/libgroupsig-static.a").abspath()
c_gl19_path =  path.Path("../../../build/lib/libgl19.a").abspath()
c_bbs04_path =  path.Path("../../../build/lib/libbbs04.a").abspath()
c_ps16_path =  path.Path("../../../build/lib/libps16.a").abspath()
c_klap20_path =  path.Path("../../../build/lib/libklap20.a").abspath()
c_kty04_path =  path.Path("../../../build/lib/libkty04.a").abspath()
c_cpy06_path =  path.Path("../../../build/lib/libcpy06.a").abspath()
c_dl21_path =  path.Path("../../../build/lib/libdl21.a").abspath()
c_dl21seq_path =  path.Path("../../../build/lib/libdl21seq.a").abspath()
c_logger_path =  path.Path("../../../build/lib/liblogger.a").abspath()
c_msg_path =  path.Path("../../../build/lib/libmsg.a").abspath()
c_base64_path =  path.Path("../../../build/lib/libbase64.a").abspath()
c_big_path =  path.Path("../../../build/lib/libbig.a").abspath()
c_hash_path =  path.Path("../../../build/lib/libhash.a").abspath()
c_pbcext_path =  path.Path("../../../build/lib/libpbcext.a").abspath()
c_crypto_path =  path.Path("../../../build/lib/libgcrypto.a").abspath()
c_math_path =  path.Path("../../../build/lib/libmath.a").abspath()
c_sys_path =  path.Path("../../../build/lib/libsys.a").abspath()
c_misc_path =  path.Path("../../../build/lib/libmisc.a").abspath()
c_mcl_path =  path.Path("../../../build/external/lib/libmcl.a").abspath()
c_mcl384_256_path = path.Path("../../../build/external/lib/libmclbn384_256.so").abspath()
c_include_mcl_path = path.Path("../../../build/external/include/mcl").abspath()
c_extlibs_path = path.Path("../../../build/external/lib").abspath()

# Specify sources and library dependencies
ffibuilder.set_source("_groupsig",
                      r"""
                      #include "groupsig.h"
                      #include "kty04.h"
                      #include "cpy06.h"
                      #include "klap20.h"
                      #include "gl19.h"
                      #include "ps16.h"
                      #include "bbs04.h"
                      """,
                      libraries=["stdc++","ssl","crypto"],
                      runtime_library_dirs=[
                          c_extlibs_path
                      ],
                      include_dirs=[
                          c_include_path,
                          c_include_mcl_path
                      ],
                      extra_objects = [
                          c_lib_path,
                          c_gl19_path,
                          c_bbs04_path,
                          c_ps16_path,
                          c_klap20_path,
                          c_kty04_path,
                          c_cpy06_path,
                          c_dl21_path,
                          c_dl21seq_path,
                          c_logger_path,
                          c_msg_path,
                          c_base64_path,
                          c_big_path,
                          c_hash_path,
                          c_pbcext_path,
                          c_crypto_path,
                          c_math_path,
                          c_sys_path,
                          c_misc_path,
                          c_mcl384_256_path,
                          c_mcl_path,
                      ], extra_link_args=["-Wl,--allow-multiple-definition"]
)

if __name__ == "__main__":
    ffibuilder.compile(verbose=True)
