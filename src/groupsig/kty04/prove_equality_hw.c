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
// #include <openssl/sha.h> /** @todo This should not be! */
/* #include <openssl/evp.h> */

#include "kty04.h"
#include "groupsig/kty04/sphere.h"
#include "groupsig/kty04/proof.h"
#include "groupsig/kty04/mem_key.h"
#include "groupsig/kty04/grp_key.h"
#include "groupsig/kty04/signature.h"
#include "bigz.h"
#include "sys/mem.h"
#include "hw/file_hw.h"

#ifdef HW3
#include "hw/params3.h"
#define HASH_DIGEST_LENGTH SIZE_SHA3/8
#else
#include "hw/params.h"
#define HASH_DIGEST_LENGTH SIZE_SHA2/8
#endif

/* Private functions */


/* Public functions */

int kty04_prove_equality(groupsig_proof_t *proof, groupsig_key_t *memkey,
			 groupsig_key_t *grpkey, groupsig_signature_t **sigs, uint16_t n_sigs) {

  kty04_grp_key_t *gkey;
  kty04_mem_key_t *mkey;
  groupsig_signature_t *sig;
  kty04_signature_t *kty04_sig;
  kty04_proof_t *kty04_proof;
  /* byte_t aux_sc[HASH_DIGEST_LENGTH+1]; */
  byte_t *aux_sc;
  // SHA_CTX aux_sha;
  /* EVP_MD_CTX *mdctx; */
  char *aux_t7r, *aux_t7, *aux_n;
  bigz_t r, t7r;
  int rc;
  uint8_t i;

  if(!proof || proof->scheme != GROUPSIG_KTY04_CODE ||
     !memkey || memkey->scheme != GROUPSIG_KTY04_CODE ||
     !grpkey || grpkey->scheme != GROUPSIG_KTY04_CODE ||
     !sigs || !n_sigs) {
    LOG_EINVAL(&logger, __FILE__, "kty04_prove_equality", __LINE__, LOGERROR);
    return IERROR;
  }

  r = NULL; t7r = NULL;
  rc = IOK;

  gkey = (kty04_grp_key_t *) grpkey->key;
  mkey = (kty04_mem_key_t *) memkey->key;
  kty04_proof = (kty04_proof_t *) proof->proof;

  if(!(r = bigz_init())) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_prove_equality", __LINE__, errno, LOGERROR);
    return IERROR;
  }

  /* Initialize the hashing environment */
  /** @todo Use EVP_* instead of SHA1_* */
  /* if((mdctx = EVP_MD_CTX_new()) == NULL) { */
  /*   LOG_ERRORCODE_MSG(&logger, __FILE__, "kty04_prove_equality", __LINE__, EDQUOT, */
  /*                     "EVP_MD_CTX_new", LOGERROR); */
  /*   GOTOENDRC(IERROR, kty04_prove_equality); */
  /* } */
  /* if(EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) { */
  /*   LOG_ERRORCODE_MSG(&logger, __FILE__, "kty04_prove_equality", __LINE__, EDQUOT, */
  /*   	      "EVP_DigestInit_ex", LOGERROR); */
  /*   GOTOENDRC(IERROR, kty04_prove_equality); */
  /* } */

  /* We get r in the same sphere as x' */
  if(sphere_get_random(gkey->inner_lambda, r) == IERROR)
    GOTOENDRC(IERROR, kty04_prove_equality);

  /* To create the proof, we make use of the T6 and T7 objects (A[5] and
     A[6], if I remember correctly). The knowledge of the discrete logarithm
     of T6 to the base T7 is used in normal signature claims. In the same way,
     given two signatures (allegedly) issued by the same member, with corresponding
     objects T6, T7, T6' and T7', we prove here that the discrete logarithm
     of T6 to the base T7 is the same to that of T6' to the base T7'. */

  /* In a kty04_signature_t, T6 is stored in A[12] and T7 in A[4] */

  /* (1) Raise the T7 field of each received signature to r, and put it into
     the hash. */
  if(!(t7r = bigz_init()))
    GOTOENDRC(IERROR, kty04_prove_equality);

  int msg_len = 0;
  // To simplify things, we create a static array enough to hold everything that is going to be hashed
  byte_t *to_be_hashed[999999] = {0};

  for(i=0; i<n_sigs; i++) {

    /* Get the next signature in the line... */
    sig = (groupsig_signature_t *) sigs[i];
    if(sig->scheme != GROUPSIG_KTY04_CODE) {
      LOG_EINVAL(&logger, __FILE__, "kty04_prove_equality", __LINE__, LOGERROR);
      GOTOENDRC(IERROR, kty04_prove_equality);
    }

    kty04_sig = (kty04_signature_t *) sig->sig;

    if(bigz_powm(t7r, kty04_sig->A[4], r, gkey->n) == IERROR)
      GOTOENDRC(IERROR, kty04_prove_equality);

    /* Put the i-th element of the array */
    if(!(aux_t7r = bigz_get_str10(t7r))) GOTOENDRC(IERROR, kty04_prove_equality);
	/* 	if(EVP_DigestUpdate(mdctx, aux_t7r, strlen(aux_t7r)) != 1) { */
    /*   LOG_ERRORCODE_MSG(&logger, __FILE__, "kty04_prove_equality", __LINE__, EDQUOT, */
	/* 		"EVP_DigestUpdate", LOGERROR); */
    /*   GOTOENDRC(IERROR, kty04_prove_equality); */
    /* } */
    strcat(to_be_hashed, aux_t7r);
    msg_len += strlen(aux_t7r);
    free(aux_t7r); aux_t7r = NULL; // review bigz_free

    /* Put the also the base (the T7's) into the hash */
    if(!(aux_t7 = bigz_get_str10(kty04_sig->A[4]))) GOTOENDRC(IERROR, kty04_prove_equality);
	/* 	if(EVP_DigestUpdate(mdctx, aux_t7, strlen(aux_t7)) != 1) { */
    /*   LOG_ERRORCODE_MSG(&logger, __FILE__, "kty04_prove_equality", __LINE__, EDQUOT, */
	/* 		"EVP_DigestUpdate", LOGERROR); */
    /*   GOTOENDRC(IERROR, kty04_prove_equality); */
    /* } */
    strcat(to_be_hashed, aux_t7);
    msg_len += strlen(aux_t7);
    free(aux_t7); aux_t7 = NULL;

  }

  /* And finally, put the modulus into the hash */
  if(!(aux_n = bigz_get_str10(gkey->n))) GOTOENDRC(IERROR, kty04_prove_equality);
  /* if(EVP_DigestUpdate(mdctx, aux_n, strlen(aux_n)) != 1) { */
  /*   LOG_ERRORCODE_MSG(&logger, __FILE__, "kty04_prove_equality", __LINE__, EDQUOT, */
  /*                     "EVP_DigestUpdate", LOGERROR); */
  /*   GOTOENDRC(IERROR, kty04_prove_equality); */
  /* } */
  strcat(to_be_hashed, aux_n);
  msg_len += strlen(aux_n);
  free(aux_n); aux_n = NULL;

  /* (2) Calculate c = hash(t7r[0] || t7[0] || ... || t7r[n-1] || t7[n-1] || mod ) */
  /* memset(aux_sc, 0, HASH_DIGEST_LENGTH+1); */
  /* if(EVP_DigestFinal_ex(mdctx, aux_sc, NULL) != 1) { */
  /*   LOG_ERRORCODE_MSG(&logger, __FILE__, "proof_equality", __LINE__, EDQUOT, */
  /*                     "EVP_DigestFinal_ex", LOGERROR); */
  /*   GOTOENDRC(IERROR, kty04_prove_equality); */
  /* } */

  aux_sc = hash_message_hw(to_be_hashed, msg_len);

  /* Now, we have to get c as a bigz_t */
  if(!(kty04_proof->c = bigz_import(aux_sc,HASH_DIGEST_LENGTH)))
    GOTOENDRC(IERROR, kty04_prove_equality);

  /* (3) To end, get s = r - c*x */
  if(!(kty04_proof->s = bigz_init()))
    GOTOENDRC(IERROR, kty04_prove_equality);

  if(bigz_mul(kty04_proof->s, kty04_proof->c, mkey->xx) == IERROR)
    GOTOENDRC(IERROR, kty04_prove_equality);

  if(bigz_sub(kty04_proof->s, r, kty04_proof->s) == IERROR)
    GOTOENDRC(IERROR, kty04_prove_equality);

  /* Free resources and exit */
 kty04_prove_equality_end:
  /* if (mdctx) EVP_MD_CTX_free(mdctx); */
  if(r) bigz_free(r);
  if(t7r) bigz_free(t7r);

  return rc;

}

/* prove_equality.c ends here */
