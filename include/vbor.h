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

#include "vsb.h"

struct vsb;

struct vbor
{
  unsigned magic;
#define VBOR_MAGIC 0x97675fd9
  uint8_t *data;
  size_t len;
};

int VBOR_Init(struct vbor *, const uint8_t *, size_t);
int VBOR_PrintJSON(struct vbor *, struct vsb *);
#define VBOR_PRINT_MULTILINE (1 << 0)
#define VBOR_PRINT_PRETTY (1 << 1)
int VBOR_Fini(struct vbor *);

struct vbob
{
  unsigned magic;
#define VBOB_MAGIC 0x3abff812
  struct vsb vsb[1];
  uint8_t *buf;
  size_t buf_len;
  /* ... */
  unsigned max_depth;
  unsigned depth;
  uint8_t open[];
};

int *VBOB_Alloc(struct vbob *, unsigned max_depth);
int VBOB_ParseJSON(struct vbor *, const char *);
int VBOB_Finish(struct vbob *, struct vbor *);
int *VBOB_Destroy(struct vbob **);

struct vboc_pos
{
  unsigned magic;
#define VBOC_POS_MAGIC 0xcf7664ba
  int pos;
  int len;
  struct vbor vbor[1];
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

#endif