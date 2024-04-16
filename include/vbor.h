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

struct vbor
{
  unsigned magic;
#define VBOR_MAGIC 0x97675fd9
  uint8_t *data;
  size_t len;
  unsigned max_depth;
};

struct vbor *VBOR_Init(const uint8_t *data, size_t len);
int VBOR_PrintJSON(struct vbor *vbor, struct vsb *json);
#define VBOR_PRINT_MULTILINE (1 << 0)
#define VBOR_PRINT_PRETTY (1 << 1)
void VBOR_Destroy(struct vbor **vbor);

uint64_t VBOR_GetUInt(struct vbor *vbor);
uint64_t VBOR_GetNegint(struct vbor *vbor);
const char *VBOR_GetString(struct vbor *vbor, size_t *len);
const uint8_t *VBOR_GetByteString(struct vbor *vbor, size_t *len);
size_t VBOR_GetArraySize(struct vbor *vbor);
size_t VBOR_GetMapSize(struct vbor *vbor);

struct vbob
{
  unsigned magic;
#define VBOB_MAGIC 0x3abff812
  struct vsb *vsb;
  unsigned max_depth;
  unsigned depth;
  uint8_t open[];
};

struct vbob *VBOB_Alloc(unsigned max_depth);
struct vbor *VBOB_ParseJSON(const char *);

void VBOB_AddUInt(struct vbob *vbob, uint64_t value);
void VBOB_AddNegint(struct vbob *vbob, uint64_t value);
void VBOB_AddString(struct vbob *vbob, const char *value, size_t len);
void VBOB_AddByteString(struct vbob *vbob, const uint8_t *value, size_t len);
void VBOB_AddArray(struct vbob *vbob, size_t num_items);
void VBOB_AddMap(struct vbob *vbob, size_t num_pairs);

struct vbor *VBOB_Finish(struct vbob *vbob);
void VBOB_Destroy(struct vbob **vbob);

struct vboc_pos
{
  unsigned magic;
#define VBOC_POS_MAGIC 0xcf7664ba
  int pos;
  int len;
  struct vbor *vbor;
};

struct vboc
{
  unsigned magic;
#define VBOC_MAGIC 0x863baac8
  const struct vbor *src;
  unsigned depth;
  unsigned max_depth;
  struct vboc_pos pos[];
};

struct vboc *VBOC_Init(const struct vbor *);
struct vbor *VBOC_Next(struct vboc *);

#endif