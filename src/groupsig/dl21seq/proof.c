/*                               -*- Mode: C -*- 
 *
 *	libgroupsig Group Signatures library
 *	Copyright (C) 2012-2013 Jesus Diaz Vico
 *
 *		
 *
 *	This file is part of the libgroupsig Group Signatures library.
 *
 *
 *  The libgroupsig library is free software: you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public License as 
 *  defined by the Free Software Foundation, either version 3 of the License, 
 *  or any later version.
 *
 *  The libroupsig library is distributed WITHOUT ANY WARRANTY; without even 
 *  the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  
 *  See the GNU Lesser General Public License for more details.
 *
 *
 *  You should have received a copy of the GNU Lesser General Public License 
 *  along with Group Signature Crypto Library.  If not, see <http://www.gnu.org/
 *  licenses/>
 *
 * @file: proof.c
 * @brief: 
 * @author: jesus
 * Maintainer: 
 * @date: lun dic 10 21:24:27 2012 (-0500)
 * @version: 
 * Last-Updated: lun ago  5 15:11:47 2013 (+0200)
 *           By: jesus
 *     Update #: 7
 * URL: 
 */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <math.h>

#include "types.h"
#include "sysenv.h"
#include "sys/mem.h"
#include "shim/base64.h"
#include "misc/misc.h"
#include "dl21seq.h"
#include "groupsig/dl21seq/proof.h"
#include "crypto/spk.h"

groupsig_proof_t* dl21seq_proof_init() {

  groupsig_proof_t *proof;
  dl21seq_proof_t *dl21seq_proof;

  if(!(proof = (groupsig_proof_t *) mem_malloc(sizeof(groupsig_proof_t)))) {
    return NULL;
  }

  proof->scheme = GROUPSIG_DL21SEQ_CODE;
  if(!(dl21seq_proof = (dl21seq_proof_t *) mem_malloc(sizeof(dl21seq_proof_t)))) {
    mem_free(proof); proof = NULL;
    return NULL;
  }
  
  if(!(dl21seq_proof->spk = spk_dlog_init())) {
    mem_free(proof); proof = NULL;
    mem_free(dl21seq_proof); dl21seq_proof = NULL;
    return NULL;
  }

  dl21seq_proof->n = 0;

  proof->proof = dl21seq_proof;

  return proof;

}

int dl21seq_proof_free(groupsig_proof_t *proof) {

  dl21seq_proof_t *dl21seq_proof;
  uint64_t i;
  
  if(!proof) {
    LOG_EINVAL_MSG(&logger, __FILE__, "dl21seq_proof_free", __LINE__,
		   "Nothing to free.", LOGWARN);
    return IERROR;
  }

  dl21seq_proof = proof->proof;

  if (dl21seq_proof) {

    if (dl21seq_proof->spk) {
      spk_dlog_free(dl21seq_proof->spk);
      dl21seq_proof->spk = NULL;
    }
    
    if (dl21seq_proof->x) {
      for (i=0; i<dl21seq_proof->n; i++) {
	if (dl21seq_proof->x[i]) {
	  mem_free(dl21seq_proof->x[i]);
	  dl21seq_proof->x[i] = NULL;
	}
      }
      mem_free(dl21seq_proof->x); dl21seq_proof->x = NULL;
    }
  
    if (dl21seq_proof->xlen) {
      mem_free(dl21seq_proof->xlen);
      dl21seq_proof->xlen = NULL;
    }

  }
  
  mem_free(proof);

  return IOK;

}

int dl21seq_proof_export(byte_t **bytes,
			 uint32_t *size,
			 groupsig_proof_t *proof) {

  dl21seq_proof_t *dl21seq_proof;
  byte_t *_bytes, *__bytes;
  int rc, _size;
  uint64_t proof_len, ctr, i;

  if(!proof || proof->scheme != GROUPSIG_DL21SEQ_CODE) {
    LOG_EINVAL(&logger, __FILE__, "dl21seq_proof_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  _bytes = NULL;
  dl21seq_proof = proof->proof;

  if ((_size = dl21seq_proof_get_size(proof)) == -1) {
    return IERROR;
  }

  if (!(_bytes = mem_malloc(sizeof(byte_t)*_size))) {
    return IERROR;
  }  

  /* Dump GROUPSIG_DL21SEQ_CODE */
  _bytes[0] = GROUPSIG_DL21SEQ_CODE;
  
  /* Dump the spk */
  __bytes = &_bytes[1];  
  if (spk_dlog_export(&__bytes,
		      &proof_len,
		      dl21seq_proof->spk) == IERROR)
    GOTOENDRC(IERROR, dl21seq_proof_export);  
  ctr += proof_len;
  
  /* Dump the sequence numbers (prepended by their length) */
  memcpy(&_bytes[ctr], &dl21seq_proof->n, sizeof(uint64_t));
  ctr += sizeof(uint64_t);

  for (i=0; i<dl21seq_proof->n; i++) {
    if (!dl21seq_proof->xlen) GOTOENDRC(IERROR, dl21seq_proof_export);
    memcpy(&_bytes[ctr], &dl21seq_proof->xlen[i], sizeof(uint64_t));
    ctr += sizeof(uint64_t);
    memcpy(&_bytes[ctr], &dl21seq_proof->x[i], dl21seq_proof->xlen[i]);
    ctr += dl21seq_proof->xlen[i];
  }

  /* Sanity check */
  if (_size != ctr) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "dl21_proof_export", __LINE__,
		      EDQUOT, "Unexpected size.", LOGERROR);
    GOTOENDRC(IERROR, dl21seq_proof_export);
  }

  /* Prepare the return */
  if(!*bytes) {
    *bytes = _bytes;
  } else {
    memcpy(*bytes, _bytes, _size);
    mem_free(_bytes); _bytes = NULL;
  }

  *size = _size;  
  
 dl21seq_proof_export_end:

  if (rc == IERROR && _bytes) { mem_free(_bytes); _bytes = NULL; }
  return rc;

}

groupsig_proof_t* dl21seq_proof_import(byte_t *source, uint32_t size) {

  groupsig_proof_t *proof;
  dl21seq_proof_t *dl21seq_proof;
  uint64_t proof_len, ctr, i;
  int rc;
  uint8_t scheme;
  
  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "dl21seq_proof_import", __LINE__, LOGERROR);
    return NULL;
  }

  rc = IOK;

  if(!(proof = dl21seq_proof_init())) {
    return NULL;
  }

  dl21seq_proof = proof->proof;  

  /* First byte: scheme */
  scheme = source[0];
  if (scheme != proof->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "dl21seq_proof_import", __LINE__, 
		      EDQUOT, "Unexpected proof scheme.", LOGERROR);
    GOTOENDRC(IERROR, dl21seq_proof_import);
  }
  ctr = 1;

  /* Read the proof */
  if (!(dl21seq_proof->spk = spk_dlog_import(&source[1], &proof_len)))
    GOTOENDRC(IERROR, dl21seq_proof_import);
  ctr += proof_len;
  
  /* Read the sequence numbers and metadata */
  memcpy(&dl21seq_proof->n, &source[ctr], sizeof(uint64_t));
  ctr += sizeof(uint64_t);

  if (dl21seq_proof->n) {
    if (!(dl21seq_proof->x =
	  (byte_t **) mem_malloc(sizeof(byte_t *)*dl21seq_proof->n)))
      GOTOENDRC(IERROR, dl21seq_proof_import);

    if (!(dl21seq_proof->xlen =
	  (uint64_t *) mem_malloc(sizeof(uint64_t)*dl21seq_proof->n)))
      GOTOENDRC(IERROR, dl21seq_proof_import);
    
    for (i=0; i<dl21seq_proof->n; i++) {
      memcpy(&dl21seq_proof->xlen[i], &source[ctr], sizeof(uint64_t));
      ctr += sizeof(uint64_t);
      memcpy(&dl21seq_proof->x, &source[ctr], dl21seq_proof->xlen[i]);
      ctr += dl21seq_proof->xlen[i];
    }

  }

  /* This trusts that the caller sets size to the exact amount of proof bytes */
  if (size != ctr) rc = IERROR;
  
 dl21seq_proof_import_end:

  if(rc == IERROR && proof) { dl21seq_proof_free(proof); proof = NULL; }
  if(rc == IOK) return proof;
  return NULL;    
  
}

int dl21seq_proof_get_size(groupsig_proof_t *proof) {

  dl21seq_proof_t *dl21seq_proof;
  uint64_t i;
  int size, sx;
  
  if (!proof) {
    LOG_EINVAL(&logger, __FILE__, "dl21seq_proof_get_size", __LINE__, LOGERROR);
    return -1;
  }

  dl21seq_proof = proof->proof;

  if ((size = spk_dlog_get_size(dl21seq_proof->spk)) == -1) {
    return -1;
  }

  for (i=0; i<dl21seq_proof->n; i++) {
    if (size + dl21seq_proof->xlen[i] > INT_MAX) return -1;
    size += dl21seq_proof->xlen[i];
  }

  if (size + sizeof(uint64_t) > INT_MAX) return -1;
  size += (dl21seq_proof->n+1)*sizeof(uint64_t);

  return size;

  
}

char* dl21seq_proof_to_string(groupsig_proof_t *proof) {

  if(!proof || proof->scheme != GROUPSIG_DL21SEQ_CODE) {
    LOG_EINVAL(&logger, __FILE__, "dl21seq_proof_to_string", __LINE__, LOGERROR);
    return NULL;
  }
  
  return NULL;

}

/* proof.c ends here */
