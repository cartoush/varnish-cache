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

#include "vdef.h"

#include "miniobj.h"
#include "vas.h"
#include "vbor.h"

typedef enum
{
  VBOR_UINT,
  VBOR_NEGINT,
  VBOR_BYTE_STRING,
  VBOR_TEXT_STRING,
  VBOR_ARRAY,
  VBOR_MAP,
  VBOR_UNKNOWN,
  VBOR_UNINIT,
} vbor_major_type_t;

typedef enum
{
  VBOR_ARG_5BITS,
  VBOR_ARG_1BYTE,
  VBOR_ARG_2BYTES,
  VBOR_ARG_4BYTES,
  VBOR_ARG_8BYTES,
  VBOR_ARG_UNKNOWN,
} vbor_argument_t;

static uint8_t
vbor_length_encoded_size(size_t size)
{
  if (size > 0xFFFFFFFF)
  {
    return 8;
  }
  if (size > 0xFFFF)
  {
    return 4;
  }
  if (size > 0xFF)
  {
    return 2;
  }
  if (size > 23)
  {
    return 1;
  }
  return 0;
}

static uint8_t
vbor_encoded_arg(size_t size)
{
  vbor_argument_t arg = VBOR_ARG_5BITS;
  if (size > 0xFFFFFFFF)
  {
    arg = VBOR_ARG_8BYTES;
  }
  else if (size > 0xFFFF)
  {
    arg = VBOR_ARG_4BYTES;
  }
  else if (size > 0xFF)
  {
    arg = VBOR_ARG_2BYTES;
  }
  else if (size > 23)
  {
    arg = VBOR_ARG_1BYTE;
  }
  else
  {
    return size;
  }
  return arg + 0x17;
}

static uint8_t
vbor_encode_type(vbor_major_type_t type)
{
  return type << 5;
}

static size_t
vbor_encode_arg(size_t size, uint8_t *data)
{
  size_t size_len = vbor_length_encoded_size(size);

  if (size_len == 0)
  {
    *data |= size;
    return 1;
  }
  size_t arg = vbor_encoded_arg(size);
  *data |= arg << 5;
  for (size_t i = 0; i < size_len; i++)
  {
    data[i] |= (size >> ((size_len - 1 - i) * 8)) & 0xFF;
  }
  return 1 + size_len;
}

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
  vbor->len = len;
  return vbor;
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
  struct vbob *vbob;
  ALLOC_OBJ(vbob, VBOB_MAGIC);
  vbob->vsb = VSB_new_auto();
  vbob->max_depth = max_depth;
  vbob->depth = 0;
  return vbob;
}

void
VBOB_Destroy(struct vbob **vbob)
{
  AN(vbob);
  VSB_destroy(&(*vbob)->vsb);
  CHECK_OBJ_NOTNULL(*vbob, VBOB_MAGIC);
  FREE_OBJ(*vbob);
}

static void
VBOB_AddHeader(struct vbob *vbob, vbor_major_type_t type, size_t len)
{
  uint8_t hdr[9] = {0};
  uint8_t written = 0;
  hdr[0] = vbor_encode_type(type);
  hdr[0] |= vbor_encoded_arg(len);
  written += 1;
  size_t size_len = vbor_length_encoded_size(len);
  if (size_len != 0)
  {
    for (size_t i = 0; i < size_len; i++)
    {
      hdr[i + 1] = (len >> ((size_len - 1 - i) * 8)) & 0xFF;
    }
    written += size_len;
  }
  AZ(VSB_bcat(vbob->vsb, hdr, written));
}

void
VBOB_AddUInt(struct vbob *vbob, uint64_t value)
{
  CHECK_OBJ_NOTNULL(vbob, VBOB_MAGIC);
  VBOB_AddHeader(vbob, VBOR_UINT, value);
}

void
VBOB_AddNegint(struct vbob *vbob, uint64_t value)
{
  CHECK_OBJ_NOTNULL(vbob, VBOB_MAGIC);
  VBOB_AddHeader(vbob, VBOR_NEGINT, value - 1);
}

void
VBOB_AddString(struct vbob *vbob, const char *value, size_t len)
{
  CHECK_OBJ_NOTNULL(vbob, VBOB_MAGIC);
  VBOB_AddHeader(vbob, VBOR_TEXT_STRING, len);
  AZ(VSB_bcat(vbob->vsb, value, len));
}

void
VBOB_AddByteString(struct vbob *vbob, const uint8_t *value, size_t len)
{
  CHECK_OBJ_NOTNULL(vbob, VBOB_MAGIC);
  VBOB_AddHeader(vbob, VBOR_BYTE_STRING, len);
  AZ(VSB_bcat(vbob->vsb, value, len));
}

void
VBOB_AddArray(struct vbob *vbob, size_t num_items)
{
  CHECK_OBJ_NOTNULL(vbob, VBOB_MAGIC);
  VBOB_AddHeader(vbob, VBOR_ARRAY, num_items);
}

void
VBOB_AddMap(struct vbob *vbob, size_t num_pairs)
{
  CHECK_OBJ_NOTNULL(vbob, VBOB_MAGIC);
  VBOB_AddHeader(vbob, VBOR_MAP, num_pairs);
}

struct vbor *
VBOB_Finish(struct vbob *vbob)
{
  CHECK_OBJ_NOTNULL(vbob, VBOB_MAGIC);
  VSB_finish(vbob->vsb);
  struct vbor *vbor = VBOR_Init(VSB_data(vbob->vsb), VSB_len(vbob->vsb));
  CHECK_OBJ_NOTNULL(vbor, VBOR_MAGIC);
  return vbor;
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

int main(void)
{
  struct vbob *vbob = VBOB_Alloc(10);

  VBOB_AddArray(vbob, 3);
  VBOB_AddUInt(vbob, 5000000000);
  VBOB_AddMap(vbob, 2);
  VBOB_AddNegint(vbob, 3000);
  VBOB_AddString(vbob, "hello", 5);
  VBOB_AddUInt(vbob, 256000);
  VBOB_AddByteString(vbob, "world", 5);
  VBOB_AddString(vbob, "goodbye", 7);
  struct vbor *vbor = VBOB_Finish(vbob);
  for (size_t i = 0; i < vbor->len; i++)
  {
    printf("%.2X ", vbor->data[i]);
  }
  printf("\n");
  

  VBOB_Destroy(&vbob);
  VBOR_Destroy(&vbor);

  return EXIT_SUCCESS;
}