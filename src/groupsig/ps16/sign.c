/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#include <stdlib.h>
#include <limits.h>

#include "ps16.h"
#include "groupsig/ps16/grp_key.h"
#include "groupsig/ps16/mem_key.h"
#include "groupsig/ps16/signature.h"
#include "shim/hash.h"
#include "shim/pbc_ext.h"
#include "sys/mem.h"

#if defined (SHA2) || defined (SHA3)
#include <openssl/evp.h>
#ifdef SHA3
#define HASH_DIGEST_LENGTH 64
#else
#define HASH_DIGEST_LENGTH 32
#endif
#endif

/* Private functions */

int ps16_sign(groupsig_signature_t *sig, message_t *msg, groupsig_key_t *memkey,
	      groupsig_key_t *grpkey, unsigned int seed) {

  pbcext_element_Fr_t *t, *k;
  pbcext_element_GT_t *e;
#if defined (SHA2) || defined (SHA3)
  byte_t aux_sc[HASH_DIGEST_LENGTH+1];
#else
  hash_t *aux_c;
#endif
  byte_t *aux_bytes;
  ps16_signature_t *ps16_sig;
  ps16_grp_key_t *ps16_grpkey;
  ps16_mem_key_t *ps16_memkey;
  uint64_t len;
  int rc;

  if(!sig || !msg ||
     !memkey || memkey->scheme != GROUPSIG_PS16_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_PS16_CODE) {
    LOG_EINVAL(&logger, __FILE__, "ps16_sign", __LINE__, LOGERROR);
    return IERROR;
  }

  ps16_sig = sig->sig;
  ps16_grpkey = grpkey->key;
  ps16_memkey = memkey->key;
  t = k = NULL;
  e = NULL;
#if !defined(SHA2) && !defined(SHA3)
  aux_c = NULL;
#endif
  aux_bytes = NULL;
  rc = IOK;

  /* Randomize sigma1 and sigma2 */
  if (!(t = pbcext_element_Fr_init())) GOTOENDRC(IERROR, ps16_sign);
  if (pbcext_element_Fr_random(t) == IERROR) GOTOENDRC(IERROR, ps16_sign);

  if (!(ps16_sig->sigma1 = pbcext_element_G1_init())) GOTOENDRC(IERROR, ps16_sign);
  if (pbcext_element_G1_mul(ps16_sig->sigma1, ps16_memkey->sigma1, t) == IERROR)
    GOTOENDRC(IERROR, ps16_sign);
  if (!(ps16_sig->sigma2 = pbcext_element_G1_init())) GOTOENDRC(IERROR, ps16_sign);
  if (pbcext_element_G1_mul(ps16_sig->sigma2, ps16_memkey->sigma2, t) == IERROR)
    GOTOENDRC(IERROR, ps16_sign);

  /* Compute signature of knowledge of sk */

  /* The SPK in PS16 is a dlog spk, but does not follow exactly the
     pattern of spk_dlog, so we must implement it manually.
     A good improvement would be to analyze how to generalize spk_dlog
     to fit this. */

  if (!(k = pbcext_element_Fr_init())) GOTOENDRC(IERROR, ps16_sign);
  if (pbcext_element_Fr_random(k) == IERROR) GOTOENDRC(IERROR, ps16_sign);

  if (!(e = pbcext_element_GT_init())) GOTOENDRC(IERROR, ps16_sign);
  if (pbcext_pairing(e, ps16_sig->sigma1, ps16_grpkey->Y) == IERROR)
    GOTOENDRC(IERROR, ps16_sign);
  if (pbcext_element_GT_pow(e, e, k) == IERROR) GOTOENDRC(IERROR, ps16_sign);

  /* c = hash(ps16_sig->sigma1,ps16_sig->sigma2,e,m); */
#if defined (SHA2) || defined (SHA3)
  EVP_MD_CTX *mdctx;
  if((mdctx = EVP_MD_CTX_new()) == NULL) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "ps16_sign", __LINE__, EDQUOT,
                      "EVP_MD_CTX_new", LOGERROR);
    GOTOENDRC(IERROR, ps16_sign);
  }
#ifdef SHA3
  if(EVP_DigestInit_ex(mdctx, EVP_sha3_512(), NULL) != 1) {
#else
  if(EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
#endif
    LOG_ERRORCODE_MSG(&logger, __FILE__, "ps16_sign", __LINE__, EDQUOT,
		      "EVP_DigestInit_ex", LOGERROR);
    GOTOENDRC(IERROR, ps16_sign);
  }
#else
  if (!(aux_c = hash_init(HASH_BLAKE2))) GOTOENDRC(IERROR, ps16_sign);
#endif

  if (pbcext_element_G1_to_bytes(&aux_bytes, &len, ps16_sig->sigma1) == IERROR)
    GOTOENDRC(IERROR, ps16_sign);
  /* Put the message into the hash */
#if defined (SHA2) || defined (SHA3)
  if(EVP_DigestUpdate(mdctx, aux_bytes, (int)len) != 1) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "ps16_sign", __LINE__, EDQUOT,
		      "EVP_DigestUpdate", LOGERROR);
    GOTOENDRC(IERROR, ps16_sign);
  }
#else
  if (hash_update(aux_c, aux_bytes, len) == IERROR)
    GOTOENDRC(IERROR, ps16_sign);
#endif
  mem_free(aux_bytes); aux_bytes = NULL;

  if (pbcext_element_G1_to_bytes(&aux_bytes, &len, ps16_sig->sigma2) == IERROR)
    GOTOENDRC(IERROR, ps16_sign);

#if defined (SHA2) || defined (SHA3)
  if(EVP_DigestUpdate(mdctx, aux_bytes, (int)len) != 1) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "ps16_sign", __LINE__, EDQUOT,
		      "EVP_DigestUpdate", LOGERROR);
    GOTOENDRC(IERROR, ps16_sign);
  }
#else
  if (hash_update(aux_c, aux_bytes, len) == IERROR)
    GOTOENDRC(IERROR, ps16_sign);
#endif
  mem_free(aux_bytes); aux_bytes = NULL;

  if (pbcext_element_GT_to_bytes(&aux_bytes, &len, e) == IERROR)
    GOTOENDRC(IERROR, ps16_sign);

#if defined (SHA2) || defined (SHA3)
  if(EVP_DigestUpdate(mdctx, aux_bytes, (int)len) != 1) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "ps16_sign", __LINE__, EDQUOT,
		      "EVP_DigestUpdate", LOGERROR);
    GOTOENDRC(IERROR, ps16_sign);
  }
#else
  if (hash_update(aux_c, aux_bytes, len) == IERROR)
    GOTOENDRC(IERROR, ps16_sign);
#endif
  mem_free(aux_bytes); aux_bytes = NULL;

#if defined (SHA2) || defined (SHA3)
  if(EVP_DigestUpdate(mdctx, msg->bytes, msg->length) != 1) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "ps16_sign", __LINE__, EDQUOT,
		      "EVP_DigestUpdate", LOGERROR);
    GOTOENDRC(IERROR, ps16_sign);
  }
  memset(aux_sc, 0, HASH_DIGEST_LENGTH+1);
#else
  if (hash_update(aux_c, msg->bytes, msg->length) == IERROR)
    GOTOENDRC(IERROR, ps16_sign);
#endif

#if defined (SHA2) || defined (SHA3)
  if(EVP_DigestFinal_ex(mdctx, aux_sc, NULL) != 1) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "ps16_sign", __LINE__, EDQUOT,
			"EVP_DigestFinal_ex", LOGERROR);
      GOTOENDRC(IERROR, ps16_sign);
  }
#else
  if (hash_finalize(aux_c) == IERROR) GOTOENDRC(IERROR, ps16_sign);
#endif

  /* Complete the sig */
  if (!(ps16_sig->c = pbcext_element_Fr_init())) GOTOENDRC(IERROR, ps16_sign);

#if defined (SHA2) || defined (SHA3)
  if (pbcext_element_Fr_from_hash(ps16_sig->c, aux_sc, HASH_DIGEST_LENGTH) == IERROR)
    GOTOENDRC(IERROR, ps16_sign);
#else
  if (pbcext_element_Fr_from_hash(ps16_sig->c, aux_c->hash, aux_c->length) == IERROR)
    GOTOENDRC(IERROR, ps16_sign);
#endif

  if (!(ps16_sig->s = pbcext_element_Fr_init())) GOTOENDRC(IERROR, ps16_sign);
  if (pbcext_element_Fr_mul(ps16_sig->s, ps16_sig->c, ps16_memkey->sk) == IERROR)
    GOTOENDRC(IERROR, ps16_sign);
  if (pbcext_element_Fr_add(ps16_sig->s, k, ps16_sig->s) == IERROR)
    GOTOENDRC(IERROR, ps16_sign);

 ps16_sign_end:

  if (k) { pbcext_element_Fr_free(k); k = NULL; }
  if (t) { pbcext_element_Fr_free(t); t = NULL; }
  if (e) { pbcext_element_GT_free(e); e = NULL; }
#if !defined(SHA2) && !defined(SHA3)
  if (aux_c) { hash_free(aux_c); aux_c = NULL; }
#endif
  if (aux_bytes) { mem_free(aux_bytes); aux_bytes = NULL; }

  if (rc == IERROR) {
    if (ps16_sig->c) {
      pbcext_element_Fr_free(ps16_sig->c);
      ps16_sig->c = NULL;
    }
    if (ps16_sig->s) {
      pbcext_element_Fr_free(ps16_sig->s);
      ps16_sig->s = NULL;
    }
    if (ps16_sig->sigma1) {
      pbcext_element_G1_free(ps16_sig->sigma1);
      ps16_sig->sigma1 = NULL;
    }
    if (ps16_sig->sigma2) {
      pbcext_element_G1_free(ps16_sig->sigma2);
      ps16_sig->sigma2 = NULL;
    }
  }
  return rc;
}

/* sign.c ends here */
