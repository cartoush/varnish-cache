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
  VBOR_TAG,
  VBOR_FLOAT_SIMPLE,

  VBOR_SIMPLE,
  VBOR_HALF_FLOAT,
  VBOR_FLOAT,
  VBOR_DOUBLE,
  VBOR_BOOL,
  VBOR_NULL,
  VBOR_UNDEFINED,
  VBOR_END,
  VBOR_UNKNOWN,
  VBOR_ERROR,
};

struct vbor
{
  unsigned magic;
#define VBOR_MAGIC 0x97675fd9
  const uint8_t *data;
  size_t len;
  unsigned max_depth;
};

struct vbor *VBOR_Alloc(const uint8_t *data, size_t len, unsigned max_depth);
struct vbor *VBOR_Clone(const struct vbor *vbor);
int VBOR_PrintJSON(struct vbor *vbor, struct vsb *json, bool pretty);
void VBOR_Destroy(struct vbor **vbor);

int VBOR_GetUInt(const struct vbor *vbor, uint64_t *res);
int VBOR_GetNegint(const struct vbor *vbor, uint64_t *res);
int VBOR_GetString(const struct vbor *vbor, const char **res, size_t *len);
int VBOR_GetByteString(const struct vbor *vbor, const uint8_t **res, size_t *len);
int VBOR_GetArraySize(const struct vbor *vbor, size_t *len);
int VBOR_GetMapSize(const struct vbor *vbor, size_t *len);
int VBOR_GetTag(const struct vbor *vbor, uint64_t *res);
int VBOR_GetSimple(const struct vbor *vbor, uint8_t *res);
int VBOR_GetBool(const struct vbor *vbor, bool *res);
int VBOR_GetFloat(const struct vbor *vbor, float *res);
int VBOR_GetDouble(const struct vbor *vbor, double *res);

enum vbor_major_type VBOR_What(const struct vbor *vbor);

struct vbob_pos
{
  size_t pos;
  size_t len;
};

struct vbob
{
  unsigned magic;
#define VBOB_MAGIC 0x3abff812
  struct vsb *vsb;
  unsigned max_depth;
  unsigned depth;
  int err;
  struct vbob_pos pos[];
};

struct vbob *VBOB_Alloc(unsigned max_depth);
int VBOB_ParseJSON(const char *json, struct vbor **vbor, unsigned max_depth);

int VBOB_AddUInt(struct vbob *vbob, uint64_t value);
int VBOB_AddNegint(struct vbob *vbob, uint64_t value);
int VBOB_AddString(struct vbob *vbob, const char *value, size_t len);
int VBOB_AddByteString(struct vbob *vbob, const uint8_t *value, size_t len);
int VBOB_AddArray(struct vbob *vbob, size_t num_items);
int VBOB_AddMap(struct vbob *vbob, size_t num_pairs);
int VBOB_AddTag(struct vbob *vbob, uint64_t value);
int VBOB_AddSimple(struct vbob *vbob, uint8_t value);
int VBOB_AddBool(struct vbob *vbob, bool value);
int VBOB_AddNull(struct vbob *vbob);
int VBOB_AddUndefined(struct vbob *vbob);
int VBOB_AddFloat(struct vbob *vbob, float value);
int VBOB_AddDouble(struct vbob *vbob, double value);

int VBOB_Finish(struct vbob *vbob, struct vbor **vbor);
void VBOB_Destroy(struct vbob **vbob);

struct vboc
{
  unsigned magic;
#define VBOC_MAGIC 0x863baac8
  struct vbor *src;
  struct vbor current[1];
};

struct vboc *VBOC_Alloc(struct vbor *vbor);
enum vbor_major_type VBOC_Next(struct vboc *vboc, struct vbor **vbor);

void VBOC_Destroy(struct vboc **vboc);

#endif