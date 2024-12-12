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

#ifndef _CPY06_GML_H
#define _CPY06_GML_H

#include "types.h"
#include "sysenv.h"
#include "include/gml.h"
#include "include/trapdoor.h"
#include "groupsig/cpy06/identity.h"
#include "cpy06.h"

/** 
 * @struct cpy06_gml_entry_data_t
 * @brief Structure for CPY06 GML entries.
 */
typedef struct {
  identity_t *id; /**< Member's ID. */
  trapdoor_t *trapdoor; /**< Member's trapdoor. */
} cpy06_gml_entry_data_t;

/* Entry public functions */

/**
 * @fn gml_entry_t* cpy06_gml_entry_init()
 * @brief Creates a new GML entry and initializes its fields.
 *
 * @return The created gml entry or NULL if error.
 */
gml_entry_t* cpy06_gml_entry_init();

/**
 * @fn int cpy06_gml_entry_free(gml_entry_t *entry)
 * @brief Frees the fields of the given GML entry.
 *
 * @param[in,out] entry The GML entry to free.
 *
 * @return IOK or IERROR
 */
int cpy06_gml_entry_free(gml_entry_t *entry);

/**
 * @fn int cpy06_gml_entry_get_size(gml_entry_t *entry)
 * @brief Returns the number of bytes needed to represent the given
 *  entry as an array of bytes.
 *
 * @param[in,out] entry The GML entry.
 *
 * @return The number of bytes needed to represent entry, or -1 if error.
 */

int cpy06_gml_entry_get_size(gml_entry_t *entry);

/**
 * @fn int cpy06_gml_entry_export(byte_t **bytes,
 *                                uint32_t *size,
 *                                gml_entry_t *entry)
 * @brief Exports a GML entry into an array of bytes.
 *
 * The used format is:
 *
 * | code (uint8_t) | identity (uint64_t) | size_SS0 | SS0 | size_SS1 | SS1 |
 *   size_ff0 | ff0 | size_ff1 | ff1 |
 *
 * @param[in,out] bytes Will be updated with the exported entry. If *entry is
 *  NULL,  memory will be internally allocated. Otherwise, it must be big enough
 *  to hold all the data.
 * @param[in,out] size Will be updated with the number of bytes written into
 *  *bytes.
 * @param[in] gml The GML structure to export.
 *
 * @return IOK or IERROR with errno set.
 */
int cpy06_gml_entry_export(byte_t **bytes, uint32_t *size,
                           gml_entry_t *entry);

/**
 * @fn gml_t* cpy06_gml_entry_import(byte_t *bytes, uint32_t size)
 * @brief Imports a GML of the specified scheme, from the given array of bytes.
 *
 * @param[in] bytes The bytes to read the GML from.
 * @param[in] size The number of bytes to be read.
 *
 * @return A pointer to the imported GML or NULL with errno set.
 */
gml_entry_t* cpy06_gml_entry_import(byte_t *bytes, uint32_t size);

/** 
 * @fn char* cpy06_gml_entry_to_string(gml_entry_t *entry)
 * @brief Converts the received CPY06 GML entry to a printable string.
 *
 * @param[in] entry The GML entry.
 * 
 * @return The converted string or NULL if error.
 */
char* cpy06_gml_entry_to_string(gml_entry_t *entry);

/* List public functions */

/** 
 * @fn gml_t* cpy06_gml_init()
 * @brief Initializes a GML structure.
 * 
 * @return A pointer to the initialized structure.
 */
gml_t* cpy06_gml_init();

/** 
 * @fn int cpy06_gml_free(gml_t *gml)
 * @brief Frees the received GML structure. 
 *
 * Note that it does not free the entries. If memory has been allocated for 
 * them, the caller must free it.
 *
 * @param[in,out] gml The GML to free.
 * 
 * @return IOK.
 */
int cpy06_gml_free(gml_t *gml);

/** 
 * @fn int cpy06_gml_insert(gml_t *gml, gml_entry_t *entry)
 * @brief Inserts the given entry into the gml. The memory pointed by the new entry is
 * not duplicated.
 *
 * @param[in,out] gml The GML.
 * @param[in] entry The entry to insert.
 * 
 * @return IOK or IERROR with errno updated.
 */
int cpy06_gml_insert(gml_t *gml, gml_entry_t *entry);

/** 
 * @fn int cpy06_gml_remove(gml_t *gml, uint64_t index)
 * @brief Removes the entry at position <i>index</i> from the GML. The caller is 
 * responsible for removing the contents of the entry itself.
 *
 * @param[in,out] gml The GML.
 * @param[in] index The index of the entry to remove.
 * 
 * @return IOK or IERROR with errno updated.
 */
int cpy06_gml_remove(gml_t *gml, uint64_t index);

/** 
 * @fn gml_entry_t* cpy06_gml_get(gml_t *gml, uint64_t index)
 * @brief Returns a pointer to the GML entry at the specified position.
 *
 * @param[in] gml The GML.
 * @param[in] index The index of the entry to retrieve.
 * 
 * @return A pointer to the specified entry or NULL if error.
 */
gml_entry_t* cpy06_gml_get(gml_t *gml, uint64_t index);

/**
 * @fn gml_t* cpy06_gml_import(byte_t *src, uint32_t size)
 * @brief Loads the Group Members List stored in the given source, and returns 
 *  an initialized GML structure.
 *
 * @param[in] src The byte array source containing the gml.
 * @param[in] size The size, in bytes, of src.
 *
 * @return The imported GML or NULL if error.
 */
gml_t* cpy06_gml_import(byte_t *src, uint32_t size);

/**
 * @fn int cpy06_gml_export(byte_t **bytes, uint32_t *size, gml_t *gml)
 * @brief Exports the given Group Members List structure into a byte array.
 *
 * @param[in] bytes Will contain the exported GML.
 * @param[in] size Will be set to the number of bytes written into <i>bytes</i>.
 * @param[in] gml The GML to export.
 *
 * @return IOK or IERROR
 */
int cpy06_gml_export(byte_t **bytes, uint32_t *size, gml_t *gml);

/* /\**  */
/*  * @fn int cpy06_gml_export_new_entry(void *entry, void *dst, gml_format_t format) */
/*  * @brief Adds the given new entry to the GML exported in the specified destination.  */
/*  * */
/*  * @param[in] entry The entry to add. */
/*  * @param[in] dst The destination */
/*  * @param[in] format The GML format. */
/*  *  */
/*  * @return IOK or IERROR. */
/*  *\/ */
/* int cpy06_gml_export_new_entry(void *entry, void *dst, gml_format_t format); */

/* /\**  */
/*  * @fn int cpy06_gml_compare_entries(void *entry1, void *entry2) */
/*  * @brief Compares two cpy06_gml_entry_t structures. Just tells if they have the same */
/*  * contents or not. */
/*  * */
/*  * @param[in] entry1 The first operand. */
/*  * @param[in] entry2 The second operand. */
/*  *  */
/*  * @return 0 if both entries have the same contents != 0 if not. If an error */
/*  *  occurs, errno is updated. */
/*  *\/ */
/* int cpy06_gml_compare_entries(void *entry1, void *entry2); */

/**
 * @var cpy06_gml_handle
 * @brief Set of functions for managing CPY06 GMLs.
 */
static const gml_handle_t cpy06_gml_handle = {
  .scheme = GROUPSIG_CPY06_CODE, /**< Scheme code. */
  .init = &cpy06_gml_init, /**< GML initialization. */
  .free = &cpy06_gml_free, /**< GML free. */
  .insert = &cpy06_gml_insert, /**< Insert a new entry. */
  .remove = &cpy06_gml_remove, /**< Remove an existing entry. */
  .get = &cpy06_gml_get, /**< Gets (without removing) a specific entry. */
  .gimport = &cpy06_gml_import, /**< Import a GML at an external source. */
  .gexport = &cpy06_gml_export, /**< Export the GML to an external destination. */
  .entry_init = &cpy06_gml_entry_init, /**< Initializes a GML entry. */
  .entry_free = &cpy06_gml_entry_free, /**< Frees a GML entry. */
  .entry_get_size = &cpy06_gml_entry_get_size,  /**< Returns the size in bytes
                                                   of a GML entry. */
  .entry_export = &cpy06_gml_entry_export, /**< Exports a GML entry. */
  .entry_import = &cpy06_gml_entry_import, /**< Imports a GML entry. */
  .entry_to_string = &cpy06_gml_entry_to_string, /**< Returns a human readable
						    string of a GML entry. */
};

#endif /* CPY06_GML_H */

/* cpy06_gml.h ends here */
