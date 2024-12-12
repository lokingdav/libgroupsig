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

#ifndef _CPY06_MEM_KEY_H
#define _CPY06_MEM_KEY_H

#include <stdint.h>
#include "types.h"
#include "sysenv.h"
#include "cpy06.h"
#include "include/mem_key.h"
#include "shim/pbc_ext.h"

/**
 * @def CPY06_MEM_KEY_BEGIN_MSG
 * @brief Begin string to prepend to headers of files containing CPY06 member keys
 */
#define CPY06_MEM_KEY_BEGIN_MSG "BEGIN CPY06 MEMBERKEY"

/**
 * @def CPY06_MEM_KEY_END_MSG
 * @brief End string to prepend to headers of files containing CPY06 member keys
 */
#define CPY06_MEM_KEY_END_MSG "END CPY06 MEMBERKEY"

/**
 * @struct cpy06_mem_key_t
 * @brief CPY06 member keys.
 */
typedef struct {
  pbcext_element_Fr_t *x; /**< x \in_R Z^*_p (non-adaptively chosen by member) */
  pbcext_element_Fr_t *t; /**< t \in_R Z^*_p (chosen by manager) */
  pbcext_element_G1_t *A; /**< A = (q*g_1^x)^(1/t+\gamma) */
  pbcext_element_Fr_t *_y; /**< Used only during the interactive join protocol.
			      Ignored in export/import. */
  pbcext_element_Fr_t *_r; /**< Used only during the interactive join protocol.
			      Ignored inn export/import. */
} cpy06_mem_key_t;

/** 
 * @fn groupsig_key_t* cpy06_mem_key_init()
 * @brief Creates a new group key.
 *
 * @return A pointer to the initialized group key or NULL in case of error.
 */
groupsig_key_t* cpy06_mem_key_init();

/** 
 * @fn int cpy06_mem_key_free(groupsig_key_t *key)
 * @brief Frees the variables of the given member key.
 *
 * @param[in,out] key The member key to initialize.
 * 
 * @return IOK or IERROR
 */
int cpy06_mem_key_free(groupsig_key_t *key);

/** 
 * @fn int cpy06_mem_key_copy(groupsig_key_t *dst, groupsig_key_t *src)
 * @brief Copies the source key into the destination key (which must be initialized 
 *  by the caller).
 *
 * @param[in,out] dst The destination key.
 * @param[in] src The source key.
 * 
 * @return IOK or IERROR.
 */
int cpy06_mem_key_copy(groupsig_key_t *dst, groupsig_key_t *src);

/** 
 * @fn int cpy06_mem_key_get_size(groupsig_key_t *key)
 * @brief Returns the size that the given key would require in order to be 
 *  represented as an array of bytes.
 *
 * @param[in] key The key.
 * 
 * @return The required number of bytes, or -1 if error.
 */
int cpy06_mem_key_get_size(groupsig_key_t *key);

/** 
 * @fn int cpy06_mem_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key)
 * @brief Writes a bytearray representation of the given key, with format:
 *
 *  | CPY06_CODE | KEYTYPE | size_params | params | size_x | x | size_t | t | 
 *    size_A | A |
 *
 * @param[in,out] bytes A pointer to the array that will contain the exported
 *  member key. If <i>*bytes</i> is NULL, memory will be internally allocated.
 * @param[in,out] size Will be set to the number of bytes written in <i>*bytes</i>.
 * @param[in] key The member key to export.
 * 
 * @return IOK or IERROR. 
 */
int cpy06_mem_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key);

/** 
 * @fn groupsig_key_t* cpy06_mem_key_import(byte_t *source, uint32_t size)
 * @brief Imports a member key.
 *
 * Imports a PS16 member key from the specified array of bytes.
 *
 * @param[in] source The array of bytes containing the key to import.
 * @param[in] source The number of bytes in the passed array.
 * 
 * @return A pointer to the imported member key, or NULL if error.
 */
groupsig_key_t* cpy06_mem_key_import(byte_t *source, uint32_t size);

/** 
 * @fn char* cpy06_mem_key_to_string(groupsig_key_t *key)
 * @brief Gets a printable representation of the specified member key.
 *
 * @param[in] key The member key.
 * 
 * @return A pointer to the obtained string, or NULL if error.
 */
char* cpy06_mem_key_to_string(groupsig_key_t *key);

/**
 * @var cpy06_mem_key_handle
 * @brief Set of functions for managing CPY06 member keys.
 */
static const mem_key_handle_t cpy06_mem_key_handle = {
  .code = GROUPSIG_CPY06_CODE, /**< The scheme code. */
  .init = &cpy06_mem_key_init, /**< Initializes member keys. */
  .free = &cpy06_mem_key_free, /**< Frees member keys. */
  .copy = &cpy06_mem_key_copy, /**< Copies member keys. */
  .get_size = &cpy06_mem_key_get_size, /**< Gets the size of the key in specific
					formats. */
  .gexport = &cpy06_mem_key_export, /**< Exports member keys. */
  .gimport = &cpy06_mem_key_import, /**< Imports member keys. */
  .to_string = &cpy06_mem_key_to_string, /**< Converts member keys to printable
					    strings. */
};

#endif /* _CPY06_MEM_KEY_H */

/* mem_key.h ends here */
