/*-
 * Copyright (c) 2024 Varnish Software AS
 * All rights reserved.
 *
 * Author: Thibaut Artis <thibaut.artis@varnish-software.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef __VBOR_H_
#define __VBOR_H_

#include "config.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "vsb.h"

enum vbor_major_type
{
  VBOR_UINT,
  VBOR_NEGINT,
  VBOR_BYTE_STRING,
  VBOR_TEXT_STRING,
  VBOR_ARRAY,
  VBOR_MAP,
  VBOR_UNKNOWN,
  VBOR_UNINIT,
};

struct vbor
{
  unsigned magic;
#define VBOR_MAGIC 0x97675fd9
  const uint8_t *data;
  size_t len;
  unsigned max_depth;
  bool sub;
};

struct vbor *VBOR_Init(const uint8_t *data, size_t len, unsigned max_depth);
int VBOR_PrintJSON(struct vbor *vbor, struct vsb *json, bool pretty);
void VBOR_Destroy(struct vbor **vbor);

uint64_t VBOR_GetUInt(const struct vbor *vbor);
uint64_t VBOR_GetNegint(const struct vbor *vbor);
const char *VBOR_GetString(const struct vbor *vbor, size_t *len);
const uint8_t *VBOR_GetByteString(const struct vbor *vbor, size_t *len);
size_t VBOR_GetArraySize(const struct vbor *vbor);
size_t VBOR_GetMapSize(const struct vbor *vbor);

enum vbor_major_type VBOR_What(const struct vbor *vbor);

struct vbob
{
  unsigned magic;
#define VBOB_MAGIC 0x3abff812
  struct vsb *vsb;
  unsigned max_depth;
  unsigned depth;
  int err;
  uint8_t open[];
};

struct vbob *VBOB_Alloc(unsigned max_depth);
int VBOB_ParseJSON(const char *json, struct vbor **vbor);

int VBOB_AddUInt(struct vbob *vbob, uint64_t value);
int VBOB_AddNegint(struct vbob *vbob, uint64_t value);
int VBOB_AddString(struct vbob *vbob, const char *value, size_t len);
int VBOB_AddByteString(struct vbob *vbob, const uint8_t *value, size_t len);
int VBOB_AddArray(struct vbob *vbob, size_t num_items);
int VBOB_AddMap(struct vbob *vbob, size_t num_pairs);

int VBOB_Finish(struct vbob *vbob, struct vbor **vbor);
void VBOB_Destroy(struct vbob **vbob);

struct vboc_pos
{
  unsigned magic;
#define VBOC_POS_MAGIC 0xcf7664ba
  size_t pos;
  size_t len;
};

struct vboc
{
  unsigned magic;
#define VBOC_MAGIC 0x863baac8
  struct vbor *src;
  struct vbor *current;
  unsigned depth;
  unsigned max_depth;
  struct vboc_pos pos[];
};

struct vboc *VBOC_Init(struct vbor *);
struct vbor *VBOC_Next(struct vboc *);
struct vboc_pos *VBOC_Where(struct vboc *vboc, size_t *depth);

void VBOC_Destroy(struct vboc **vboc);

#endif