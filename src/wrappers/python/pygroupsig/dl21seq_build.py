# file "dl21seq_build"

from pygroupsig.common_build import ffibuilder

ffibuilder.cdef("#define GROUPSIG_DL21SEQ_CODE 7")
#ffibuilder.cdef('#define GROUPSIG_DL21SEQ_NAME "DL21SEQ"')
ffibuilder.cdef("#define DL21SEQ_JOIN_START 0")
ffibuilder.cdef("#define DL21SEQ_JOIN_SEQ 3")

ffibuilder.cdef("""
int dl21seq_init();
""")

ffibuilder.cdef("""
int dl21seq_clear();
""")

ffibuilder.cdef("""
int dl21seq_setup(
groupsig_key_t *grpkey,
groupsig_key_t *mgrkey,
gml_t *gml);
""")

ffibuilder.cdef("""
int dl21seq_get_joinseq(uint8_t *seq);
""")

ffibuilder.cdef("""
int dl21seq_get_joinstart(uint8_t *start);
""")

ffibuilder.cdef("""
int dl21seq_join_mem(
message_t **mout,
groupsig_key_t *memkey,
int seq,
message_t *min,
groupsig_key_t *grpkey);
""")

ffibuilder.cdef("""
int dl21seq_join_mgr(
message_t **mout,
gml_t *gml,
groupsig_key_t *mgrkey,
int seq,
message_t *min,
groupsig_key_t *grpkey);
""")

ffibuilder.cdef("""
int dl21seq_sign(
groupsig_signature_t *sig,
message_t *msg,
groupsig_key_t *memkey,
groupsig_key_t *grpkey,
unsigned int seed);
""")

ffibuilder.cdef("""
int dl21seq_verify(
uint8_t *ok,
groupsig_signature_t *sig,
message_t *msg,
groupsig_key_t *grpkey);
""")

ffibuilder.cdef("""
int dl21seq_identify(uint8_t *ok,
groupsig_proof_t **proof,
groupsig_key_t *grpkey,
groupsig_key_t *memkey,
groupsig_signature_t *sig,
message_t *msg);
""")

ffibuilder.cdef("""
int dl21seq_link(groupsig_proof_t **proof,
groupsig_key_t *grpkey,
groupsig_key_t *memkey,
message_t *msg,
groupsig_signature_t **sigs,
message_t **msgs,
uint32_t n);
""")

ffibuilder.cdef("""
int dl21seq_verify_link(uint8_t *ok,
groupsig_key_t *grpkey,
groupsig_proof_t *proof,
message_t *msg,
groupsig_signature_t **sigs,
message_t **msgs,
uint32_t n);
""")

ffibuilder.cdef("""
int dl21seq_seqlink(groupsig_proof_t **proof,
groupsig_key_t *grpkey,
groupsig_key_t *memkey,
message_t *msg,
groupsig_signature_t **sigs,
message_t **msgs,
uint32_t n);
""")

ffibuilder.cdef("""
int dl21seq_verify_seqlink(uint8_t *ok,
groupsig_key_t *grpkey,
groupsig_proof_t *proof,
message_t *msg,
groupsig_signature_t **sigs,
message_t **msgs,
uint32_t n);
""")
