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

#include "config.h"

#include <string.h>

#include "miniobj.h"
#include "vas.h"
#include "vbor.h"

struct vbor *
VBOR_Init(const uint8_t *data, size_t len)
{
  struct vbor *vbor;
  AN(data);
  AN(len);
  ALLOC_OBJ(vbor, VBOR_MAGIC);
  vbor->data = malloc(len);
  AN(vbor->data);
  memcpy(vbor->data, data, len);
}

int
VBOR_PrintJSON(struct vbor *vbor, struct vsb *json)
{

}

void
VBOR_Destroy(struct vbor **vbor)
{
  AN(vbor);
  AN((*vbor)->data);
  free((*vbor)->data);
  FREE_OBJ(*vbor);
}

uint64_t
VBOR_GetUInt(struct vbor *vbor)
{

}

int64_t
VBOR_GetNegint(struct vbor *vbor)
{

}

const char *
VBOR_GetString(struct vbor *vbor)
{

}

const uint8_t *
VBOR_GetByteString(struct vbor *vbor)
{

}

struct vbob *
VBOB_Alloc(unsigned max_depth)
{

}

void
VBOB_Destroy(struct vbob **vbob)
{

}

bool
VBOB_AddUInt(struct vbob *vbob, uint64_t value)
{

}

bool
VBOB_AddNegint(struct vbob *vbob, int64_t value)
{

}

bool
VBOB_AddString(struct vbob *vbob, const char *value, size_t len)
{

}

bool
VBOB_AddByteString(struct vbob *vbob, const uint8_t *value, size_t len)
{

}

bool
VBOB_AddArray(struct vbob *vbob, size_t num_items)
{

}

bool
VBOB_AddMap(struct vbob *vbob, size_t num_pairs)
{

}

struct vbor *
VBOB_Finish(struct vbob *vbob)
{

}

struct vbor *
VBOB_ParseJSON(const char *json)
{

}

struct vboc *
VBOC_Init(const struct vbor *vbor)
{
  struct vboc *vboc;
  CHECK_OBJ_NOTNULL(vbor, VBOR_MAGIC);
  ALLOC_OBJ_EXTRA(vboc, sizeof(struct vboc_pos) * vbor->max_depth, VBOC_MAGIC);
  ALLOC_OBJ(vboc, VBOC_MAGIC);
  vboc->src = vbor;
  vboc->depth = 0;
  vboc->max_depth = vbor->max_depth;
  for (unsigned i = 0; i < vboc->max_depth; i++) {
    vboc->pos[i].magic = VBOC_POS_MAGIC;
  }
  return vboc;
}

struct vbor *
VBOC_Next(struct vboc *)
{

}
