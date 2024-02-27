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

#ifndef _CRL_HANDLES_H
#define _CRL_HANDLES_H

#include "crl.h"
#include "groupsig/kty04/crl.h"
/* #include "groupsig/bbs04/crl.h" */
#include "groupsig/cpy06/crl.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @def CRL_HANDLES_N
 * @brief Number of supported CRL implementations.
 */
#define CRL_HANDLES_N 2

/**
 * @var CRL_HANDLES
 * @brief List of handles of CRL implementations.
 */
const crl_handle_t *CRL_HANDLES[CRL_HANDLES_N] = {
  &kty04_crl_handle,
  /* &bbs04_crl_handle, */
  &cpy06_crl_handle,
};

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/* Write any cplusplus specific code here */
#endif

#endif /* _CRL_HANDLES_H */

/* crl_handles.h ends here */
