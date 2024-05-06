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

#include <ctype.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

#include "vdef.h"

#include "miniobj.h"
#include "vas.h"
#include "vbor.h"
#include "venc.h"

enum vbor_argument
{
  VBOR_ARG_5BITS,
  VBOR_ARG_1BYTE,
  VBOR_ARG_2BYTES,
  VBOR_ARG_4BYTES,
  VBOR_ARG_8BYTES,
  VBOR_ARG_UNKNOWN,
};

static void
invert_bytes(uint8_t *val, uint8_t len)
{
  uint8_t tmp = 0;
  for (uint8_t i = 0; i < len / 2; i++)
  {
    tmp = val[i];
    val[i] = val[len - i - 1];
    val[len - i - 1] = tmp;
  }
}

static uint8_t
vbor_length_encoded_size(size_t size)
{
  if (size > 0xFFFFFFFF)
    return 8;
  if (size > 0xFFFF)
    return 4;
  if (size > 0xFF)
    return 2;
  if (size > 23)
    return 1;
  return 0;
}

static uint8_t
vbor_encoded_arg(size_t size)
{
  enum vbor_argument arg = VBOR_ARG_5BITS;
  if (size > 0xFFFFFFFF)
    arg = VBOR_ARG_8BYTES;
  else if (size > 0xFFFF)
    arg = VBOR_ARG_4BYTES;
  else if (size > 0xFF)
    arg = VBOR_ARG_2BYTES;
  else if (size > 23)
    arg = VBOR_ARG_1BYTE;
  else
    return size;
  return arg + 0x17;
}

static uint8_t
vbor_encode_type(enum vbor_major_type type)
{
  return type << 5;
}

static enum vbor_major_type
vbor_decode_type(uint8_t data)
{
  enum vbor_major_type type = data >> 5;

  if (type > VBOR_FLOAT_SIMPLE)
    type = VBOR_UNKNOWN;
  if (type == VBOR_FLOAT_SIMPLE)
  {
    if (data >= (VBOR_FLOAT_SIMPLE << 5) + 28)
      type = VBOR_ERROR;
    else {
      switch (data)
      {
      case (VBOR_FLOAT_SIMPLE << 5) + 27:
        type = VBOR_DOUBLE;
        break;
      case (VBOR_FLOAT_SIMPLE << 5) + 26:
        type = VBOR_FLOAT;
        break;
      case (VBOR_FLOAT_SIMPLE << 5) + 25:
        type = VBOR_ERROR; // Half-float not supported
        break;
      case (VBOR_FLOAT_SIMPLE << 5) + 23:
        type = VBOR_UNDEFINED;
        break;
      case (VBOR_FLOAT_SIMPLE << 5) + 22:
        type = VBOR_NULL;
        break;
      case (VBOR_FLOAT_SIMPLE << 5) + 21:
      case (VBOR_FLOAT_SIMPLE << 5) + 20:
        type = VBOR_BOOL;
        break;
      case (VBOR_FLOAT_SIMPLE << 5) + 24:
      default:
        type = VBOR_SIMPLE;
        break;
      }
    }
  }
  return type;
}

static enum vbor_argument
vbor_decode_arg(uint8_t data)
{
  enum vbor_argument arg = data & 0b00011111;

  if (arg > 0x1b)
    arg = VBOR_ARG_UNKNOWN;
  else if (arg < 0x18)
    arg = VBOR_ARG_5BITS;
  else
    arg = arg - 0x17;
  return arg;
}

static size_t
vbor_decode_value_length(enum vbor_major_type type, enum vbor_argument arg, const uint8_t *data, size_t length)
{
  size_t len = 0;
  if (type == VBOR_UNKNOWN || arg == VBOR_ARG_UNKNOWN)
    return -1;
  else if (arg == VBOR_ARG_5BITS)
    len = (*data) & 0b00011111;
  else
  {
    uint8_t len_len = pow(2, arg - 1);
    if (len_len > length - 1)
      return -1;
    for (size_t i = 0; i < len_len; i++)
    {
      len <<= 8;
      len += data[1 + i];
    }
  }
  return len;
}

struct vbor *
VBOR_Alloc(const uint8_t *data, size_t len, unsigned max_depth)
{
  struct vbor *vbor;
  AN(data);
  AN(len);
  ALLOC_OBJ(vbor, VBOR_MAGIC);
  vbor->data = malloc(len);
  AN(vbor->data);
  memcpy((void*)vbor->data, data, len);
  vbor->len = len;
  vbor->max_depth = max_depth;
  return vbor;
}

struct vbor *
VBOR_Clone(const struct vbor *vbor)
{
  CHECK_OBJ_NOTNULL(vbor, VBOR_MAGIC);
  return VBOR_Alloc(vbor->data, vbor->len, vbor->max_depth);
}

static int
VBOR_InitSub(const uint8_t *data, size_t len, unsigned super_depth, struct vbor *vbor)
{
  CHECK_OBJ_NOTNULL(vbor, VBOR_MAGIC);
  AN(data);
  if (len == 0)
    return -1;
  vbor->data = data;
  vbor->len = len;
  switch (VBOR_What(vbor)) {
  case VBOR_ERROR:
  case VBOR_UNKNOWN:
    return -1;
  case VBOR_ARRAY:
  case VBOR_MAP:
    vbor->max_depth = super_depth - 1;
    break;
  default:
    vbor->max_depth = super_depth;
    break;
  }
  return 0;
}

int
VBOR_PrintJSON(struct vbor *vbor, struct vsb *json, unsigned pretty)
{
  CHECK_OBJ_NOTNULL(vbor, VBOR_MAGIC);
  CHECK_OBJ_NOTNULL(json, VSB_MAGIC);
  struct vboc *vboc = VBOC_Alloc(vbor);
  CHECK_OBJ_NOTNULL(vboc, VBOC_MAGIC);
  size_t idxs[vbor->max_depth];
  enum vbor_major_type types[vbor->max_depth];
  size_t depth = -1;
  size_t initial_len = VSB_len(json);

  struct vbor *next;
  enum vbor_major_type type;
  while ((type = VBOC_Next(vboc, &next)) < VBOR_END) {
    if (type == VBOR_TAG) {
      continue;
    }
    if (pretty && depth != (size_t)-1 && !(types[depth] == VBOR_MAP && idxs[depth] % 2 == 1))
    {
      for (size_t i = 0; i < depth + 1; i++)
        VSB_putc(json, '\t');
    }
    switch (type)
    {
    case VBOR_UINT:;
      uint64_t uval = 0;
      if (VBOR_GetUInt(next, &uval))
        return -1;
      VSB_printf(json, "%lu", uval);
      break;
    case VBOR_NEGINT:;
      uint64_t nval = 0;
      if (VBOR_GetNegint(next, &nval))
        return -1;
      VSB_printf(json, "-%lu", nval);
      break;
    case VBOR_TEXT_STRING:;
      size_t tdata_len = 0;
      const char *tdata = NULL;
      if (VBOR_GetString(next, (const char**)&tdata, &tdata_len))
        return -1;
      VSB_putc(json, '"');
      VSB_bcat(json, tdata, tdata_len);
      VSB_putc(json, '"');
      break;
    case VBOR_BYTE_STRING:;
      size_t bdata_len = 0;
      const uint8_t *bdata = NULL;
      if (VBOR_GetByteString(next, &bdata, &bdata_len))
        return -1;
      VSB_putc(json, '"');
      VENC_Encode_Base64(json, bdata, bdata_len);
      VSB_putc(json, '"');
      break;
    case VBOR_ARRAY:;
      size_t num_items = 0;
      VSB_printf(json, "[");
      depth++;
      if (VBOR_GetArraySize(next, &num_items))
        return -1;
      idxs[depth] = num_items;
      types[depth] = VBOR_ARRAY;
      break;
    case VBOR_MAP:;
      size_t num_pairs = 0;
      VSB_printf(json, "{");
      depth++;
      if (VBOR_GetMapSize(next, &num_pairs))
        return -1;
      idxs[depth] = num_pairs * 2;
      types[depth] = VBOR_MAP;
      break;
    case VBOR_SIMPLE:;
      uint8_t sval = 0;
      if (VBOR_GetSimple(next, &sval))
        return -1;
      VSB_printf(json, "%u", sval);
      break;
    case VBOR_FLOAT:;
      float fval = 0;
      if (VBOR_GetFloat(next, &fval))
        return -1;
      VSB_printf(json, "%f", fval);
      break;
    case VBOR_DOUBLE:;
      double dval = 0;
      if (VBOR_GetDouble(next, &dval))
        return -1;
      VSB_printf(json, "%f", dval);
      break;
    case VBOR_BOOL:;
      unsigned bval;
      if (VBOR_GetBool(next, &bval))
        return -1;
      VSB_printf(json, "%s", bval ? "true" : "false");
      break;
    case VBOR_NULL:
      VSB_printf(json, "null");
      break;
    case VBOR_UNDEFINED:
      VSB_printf(json, "undefined");
      break;
    default:
      break;
    }
    if (type != VBOR_ARRAY && type != VBOR_MAP && depth != (size_t)-1)
      idxs[depth]--;
    if (depth != (size_t)-1 && idxs[depth] == 0)
    {
      while (depth != (size_t)-1 && idxs[depth] == 0)
      {
        if (pretty)
        {
          VSB_putc(json, '\n');
          for (size_t i = 0; i < depth; i++)
            VSB_putc(json, '\t');
        }
        switch (types[depth])
        {
        case VBOR_ARRAY:
          VSB_putc(json, ']');
          break;
        case VBOR_MAP:
          VSB_putc(json, '}');
          break;
        default:
          VBOC_Destroy(&vboc);
          return -1;
        }
        depth--;
        idxs[depth]--;
      }
    }
    if (type != VBOR_ARRAY && type != VBOR_MAP && depth != (size_t)-1 && idxs[depth] != 0)
    {
      if (types[depth] == VBOR_MAP && idxs[depth] % 2 == 1)
        VSB_putc(json, ':');
      else
      {
        VSB_putc(json, ',');
        if (pretty)
          VSB_putc(json, '\n');
      }
    }
    else if (pretty)
      VSB_putc(json, '\n');
  }
  VBOC_Destroy(&vboc);
  return VSB_len(json) - initial_len;
}

void
VBOR_Destroy(struct vbor **vbor)
{
  CHECK_OBJ_NOTNULL(*vbor, VBOR_MAGIC);
  AN((*vbor)->data);
  free((void*)(*vbor)->data);
  FREE_OBJ(*vbor);
}

static unsigned
VBOR_GetTypeArg(const struct vbor *vbor, enum vbor_major_type *type, enum vbor_argument *arg)
{
  CHECK_OBJ_NOTNULL(vbor, VBOR_MAGIC);
  AN(type);
  AN(arg);
  *type = vbor_decode_type(vbor->data[0]);
  if (*type == VBOR_UNKNOWN)
    return 0;
  *arg = vbor_decode_arg(vbor->data[0]);
  if (*arg == VBOR_ARG_UNKNOWN)
    return 0;
  return 1;
}

static unsigned
VBOR_GetHeader(const struct vbor *vbor, enum vbor_major_type *type, enum vbor_argument *arg, size_t *len)
{
  CHECK_OBJ_NOTNULL(vbor, VBOR_MAGIC);
  AN(type);
  AN(arg);
  AN(len);
  if (!VBOR_GetTypeArg(vbor, type, arg))
    return 0;
  *len = vbor_decode_value_length(*type, *arg, vbor->data, vbor->len);
  if (*len == (size_t)-1)
    return 0;
  return 1;
}

int
VBOR_GetUInt(const struct vbor *vbor, uint64_t *res)
{
  CHECK_OBJ_NOTNULL(vbor, VBOR_MAGIC);
  AN(res);
  enum vbor_major_type type = VBOR_UNKNOWN;
  enum vbor_argument arg = VBOR_ARG_UNKNOWN;
  size_t len = - 1;
  if (!VBOR_GetHeader(vbor, &type, &arg, &len))
    return -1;
  if (type != VBOR_UINT)
    return -1;
  *res = len;
  return 0;
}

int
VBOR_GetNegint(const struct vbor *vbor, uint64_t *res)
{
  CHECK_OBJ_NOTNULL(vbor, VBOR_MAGIC);
  AN(res);
  enum vbor_major_type type = VBOR_UNKNOWN;
  enum vbor_argument arg = VBOR_ARG_UNKNOWN;
  size_t len = - 1;
  if (!VBOR_GetHeader(vbor, &type, &arg, &len))
    return -1;
  if (type != VBOR_NEGINT)
    return -1;
  *res = len + 1;
  return 0;
}

int VBOR_GetString(const struct vbor *vbor, const char **res, size_t *len)
{
  CHECK_OBJ_NOTNULL(vbor, VBOR_MAGIC);
  AN(len);
  enum vbor_major_type type = VBOR_UNKNOWN;
  enum vbor_argument arg = VBOR_ARG_UNKNOWN;
  *len = -1;
  if (!VBOR_GetHeader(vbor, &type, &arg, len))
    return -1;
  if (type != VBOR_TEXT_STRING)
    return -1;
  *res = (const char*)vbor->data + 1 + vbor_length_encoded_size(*len);
  return 0;
}

int
VBOR_GetByteString(const struct vbor *vbor, const uint8_t **res, size_t *len)
{
  CHECK_OBJ_NOTNULL(vbor, VBOR_MAGIC);
  AN(len);
  enum vbor_major_type type = VBOR_UNKNOWN;
  enum vbor_argument arg = VBOR_ARG_UNKNOWN;
  *len = - 1;
  if (!VBOR_GetHeader(vbor, &type, &arg, len))
    return -1;
  if (type != VBOR_BYTE_STRING)
    return -1;
  *res = vbor->data + 1 + vbor_length_encoded_size(*len);
  return 0;
}

int
VBOR_GetArraySize(const struct vbor *vbor, size_t *len)
{
  CHECK_OBJ_NOTNULL(vbor, VBOR_MAGIC);
  AN(len);
  enum vbor_major_type type = VBOR_UNKNOWN;
  enum vbor_argument arg = VBOR_ARG_UNKNOWN;
  if (!VBOR_GetHeader(vbor, &type, &arg, len))
    return -1;
  if (type != VBOR_ARRAY)
    return -1;
  return 0;
}

int
VBOR_GetMapSize(const struct vbor *vbor, size_t *len)
{
  CHECK_OBJ_NOTNULL(vbor, VBOR_MAGIC);
  AN(len);
  enum vbor_major_type type = VBOR_UNKNOWN;
  enum vbor_argument arg = VBOR_ARG_UNKNOWN;
  if (!VBOR_GetHeader(vbor, &type, &arg, len))
    return -1;
  if (type != VBOR_MAP)
    return -1;
  return 0;
}

int
VBOR_GetTag(const struct vbor *vbor, uint64_t *res)
{
  CHECK_OBJ_NOTNULL(vbor, VBOR_MAGIC);
  AN(res);
  enum vbor_major_type type = VBOR_UNKNOWN;
  enum vbor_argument arg = VBOR_ARG_UNKNOWN;
  size_t len = -1;
  if (!VBOR_GetHeader(vbor, &type, &arg, &len))
    return -1;
  if (type != VBOR_TAG)
    return -1;
  *res = len;
  return 0;
}

int
VBOR_GetSimple(const struct vbor *vbor, uint8_t *res)
{
  CHECK_OBJ_NOTNULL(vbor, VBOR_MAGIC);
  AN(res);
  enum vbor_major_type type = VBOR_UNKNOWN;
  enum vbor_argument arg = VBOR_ARG_UNKNOWN;
  if (!VBOR_GetTypeArg(vbor, &type, &arg))
    return -1;
  if (type != VBOR_SIMPLE)
    return -1;
  if (arg == VBOR_ARG_5BITS)
    *res = vbor->data[0] & 0b00011111;
  else if (arg == VBOR_ARG_1BYTE)
    *res = vbor->data[1];
  else
    return -1;
  if (*res >= 24 && *res < 32)
    return -1;
  return 0;
}

int
VBOR_GetFloat(const struct vbor *vbor, float *res)
{
  CHECK_OBJ_NOTNULL(vbor, VBOR_MAGIC);
  AN(res);
  enum vbor_major_type type = VBOR_UNKNOWN;
  enum vbor_argument arg = VBOR_ARG_UNKNOWN;
  if (!VBOR_GetTypeArg(vbor, &type, &arg))
    return -1;
  if (type != VBOR_FLOAT)
    return -1;
  if (arg != VBOR_ARG_4BYTES)
    return -1;
  memcpy(res, vbor->data + 1, 4);
  invert_bytes((uint8_t*)res, 4);
  return 0;
}

int
VBOR_GetDouble(const struct vbor *vbor, double *res)
{
  CHECK_OBJ_NOTNULL(vbor, VBOR_MAGIC);
  AN(res);
  enum vbor_major_type type = VBOR_UNKNOWN;
  enum vbor_argument arg = VBOR_ARG_UNKNOWN;
  if (!VBOR_GetTypeArg(vbor, &type, &arg))
    return -1;
  if (type != VBOR_DOUBLE)
    return -1;
  if (arg != VBOR_ARG_8BYTES)
    return -1;
  memcpy(res, vbor->data + 1, 8);
  invert_bytes((uint8_t *)res, 8);
  return 0;
}

int
VBOR_GetBool(const struct vbor *vbor, unsigned *res)
{
  CHECK_OBJ_NOTNULL(vbor, VBOR_MAGIC);
  AN(res);
  if (vbor->data[0] != 0xF4 && vbor->data[0] != 0xF5)
    return -1;
  *res = vbor->data[0] == 0xF5;
  return 0;
}

enum vbor_major_type
VBOR_What(const struct vbor *vbor)
{
  CHECK_OBJ_NOTNULL(vbor, VBOR_MAGIC);
  AN(vbor->data);
  AN(vbor->len);
  return vbor_decode_type(vbor->data[0]);
}

struct vbob *
VBOB_Alloc(unsigned max_depth)
{
  struct vbob *vbob;
  ALLOC_FLEX_OBJ(vbob, pos, max_depth, VBOB_MAGIC);
  vbob->vsb = VSB_new_auto();
  vbob->max_depth = max_depth;
  vbob->depth = -1;
  vbob->err = 0;
  memset(vbob->pos, 0, sizeof(struct vbob_pos) * max_depth);
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

static int
VBOB_Update_cursor(struct vbob *vbob, enum vbor_major_type type, size_t len)
{
  if (type != VBOR_ARRAY && type != VBOR_MAP)
  {
    if (vbob->depth == (unsigned)-1)
    {
      if (VSB_len(vbob->vsb) != 0)
      {
        vbob->err = -1;
        return vbob->err;
      }
      return 0;
    }
    else if (type != VBOR_TAG)
      vbob->pos[vbob->depth].pos += 1;
  }
  else
  {
    if (vbob->depth == (unsigned)-1 && vbob->pos[0].len != 0 && vbob->pos[0].pos >= vbob->pos[0].len)
    {
      vbob->err = -1;
      return vbob->err;
    }
    vbob->depth++;
    if (vbob->depth >= vbob->max_depth)
    {
      vbob->err = -1;
      return vbob->err;
    }
    vbob->pos[vbob->depth].len = type == VBOR_ARRAY ? len : len * 2;
    vbob->pos[vbob->depth].pos = 0;
  }
  if (vbob->depth != (unsigned)-1 && vbob->pos[vbob->depth].pos >= vbob->pos[vbob->depth].len)
  {
    while (vbob->depth != (unsigned)-1 && vbob->pos[vbob->depth].pos >= vbob->pos[vbob->depth].len)
    {
      vbob->depth--;
      if (vbob->depth != (unsigned)-1)
        vbob->pos[vbob->depth].pos += 1;
    }
    if (vbob->depth == (unsigned)-1 && vbob->pos[0].pos != 0 && vbob->pos[0].pos > vbob->pos[0].len)
    {
      vbob->err = -1;
      return vbob->err;
    }
  }
  return 0;
}

static int
VBOB_AddHeader(struct vbob *vbob, enum vbor_major_type type, size_t len)
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
      hdr[i + 1] = (len >> ((size_len - 1 - i) * 8)) & 0xFF;
    written += size_len;
  }
  return VSB_bcat(vbob->vsb, hdr, written);
}

int
VBOB_AddUInt(struct vbob *vbob, uint64_t value)
{
  CHECK_OBJ_NOTNULL(vbob, VBOB_MAGIC);
  if (vbob->err)
    return vbob->err;
  vbob->err = VBOB_Update_cursor(vbob, VBOR_UINT, 0);
  if (!vbob->err)
    vbob->err = VBOB_AddHeader(vbob, VBOR_UINT, value);
  return vbob->err;
}

int
VBOB_AddNegint(struct vbob *vbob, uint64_t value)
{
  CHECK_OBJ_NOTNULL(vbob, VBOB_MAGIC);
  if (vbob->err)
    return vbob->err;
  vbob->err = VBOB_Update_cursor(vbob, VBOR_NEGINT, 0);
  if (!vbob->err)
    vbob->err = VBOB_AddHeader(vbob, VBOR_NEGINT, value - 1);
  return vbob->err;
}

int
VBOB_AddString(struct vbob *vbob, const char *value, size_t len)
{
  CHECK_OBJ_NOTNULL(vbob, VBOB_MAGIC);
  if (vbob->err)
    return vbob->err;
  vbob->err = VBOB_Update_cursor(vbob, VBOR_TEXT_STRING, 0);
  if (!vbob->err)
    vbob->err = VBOB_AddHeader(vbob, VBOR_TEXT_STRING, len);
  if (!vbob->err)
    vbob->err = VSB_bcat(vbob->vsb, value, len);
  return vbob->err;
}

int
VBOB_AddByteString(struct vbob *vbob, const uint8_t *value, size_t len)
{
  CHECK_OBJ_NOTNULL(vbob, VBOB_MAGIC);
  if (vbob->err)
    return vbob->err;
  vbob->err = VBOB_Update_cursor(vbob, VBOR_BYTE_STRING, 0);
  if (!vbob->err)
    vbob->err = VBOB_AddHeader(vbob, VBOR_BYTE_STRING, len);
  if (!vbob->err)
    vbob->err = VSB_bcat(vbob->vsb, value, len);
  return vbob->err;
}

int
VBOB_AddArray(struct vbob *vbob, size_t num_items)
{
  CHECK_OBJ_NOTNULL(vbob, VBOB_MAGIC);
  if (vbob->err)
    return vbob->err;
  vbob->err = VBOB_Update_cursor(vbob, VBOR_ARRAY, num_items);
  if (!vbob->err)
    vbob->err = VBOB_AddHeader(vbob, VBOR_ARRAY, num_items);
  return vbob->err;
}

int
VBOB_AddMap(struct vbob *vbob, size_t num_pairs)
{
  CHECK_OBJ_NOTNULL(vbob, VBOB_MAGIC);
  if (vbob->err)
    return vbob->err;
  vbob->err = VBOB_Update_cursor(vbob, VBOR_MAP, num_pairs);
  if (!vbob->err)
    vbob->err = VBOB_AddHeader(vbob, VBOR_MAP, num_pairs);
  return vbob->err;
}

int
VBOB_AddTag(struct vbob *vbob, uint64_t value)
{
  CHECK_OBJ_NOTNULL(vbob, VBOB_MAGIC);
  if (vbob->err)
    return vbob->err;
  vbob->err = VBOB_Update_cursor(vbob, VBOR_TAG, 0);
  if (!vbob->err)
    vbob->err = VBOB_AddHeader(vbob, VBOR_TAG, value);
  return vbob->err;
}

static int
VBOB_AddHeaderFloat(struct vbob *vbob, char len)
{
  switch (len) {
    case 8:
      len = 27;
      break;
    case 4:
      len = 26;
      break;
    case 1:
      len = 24;
      break;
    case 0:
      break;
    case 2:
    // Half precision floats not supported (yet?)
    default:
      return -1;
  }
  char hdr = (VBOR_FLOAT_SIMPLE << 5) | len;
  return VSB_bcat(vbob->vsb, &hdr, 1);
}

int
VBOB_AddSimple(struct vbob *vbob, uint8_t value)
{
  CHECK_OBJ_NOTNULL(vbob, VBOB_MAGIC);
  if (vbob->err)
    return vbob->err;
  vbob->err = VBOB_Update_cursor(vbob, VBOR_FLOAT_SIMPLE, 0);
  uint8_t wr[2];
  wr[0] = VBOR_FLOAT_SIMPLE << 5; 
  if (value <= 23)
  {
    wr[0] |= value;
    return VSB_bcat(vbob->vsb, wr, 1);
  }
  else if (value < 32)
  {
    vbob->err = -1;
    return vbob->err;
  }
  wr[0] |= 24;
  wr[1] = value;
  return VSB_bcat(vbob->vsb, wr, 2);
}

int
VBOB_AddBool(struct vbob *vbob, unsigned value)
{
  return VBOB_AddSimple(vbob, value ? 21 : 20);
}

int
VBOB_AddNull(struct vbob *vbob)
{
  return VBOB_AddSimple(vbob, 22);
}

int
VBOB_AddUndefined(struct vbob *vbob)
{
  return VBOB_AddSimple(vbob, 23);
}

int
VBOB_AddFloat(struct vbob *vbob, float value)
{
  CHECK_OBJ_NOTNULL(vbob, VBOB_MAGIC);
  if (vbob->err)
    return vbob->err;
  vbob->err = VBOB_Update_cursor(vbob, VBOR_FLOAT_SIMPLE, 0);
  if (vbob->err)
    return vbob->err;
  vbob->err = VBOB_AddHeaderFloat(vbob, 4);
  if (vbob->err)
    return vbob->err;
  invert_bytes((uint8_t*)&value, 4);
  return VSB_bcat(vbob->vsb, &value, 4);
}

int
VBOB_AddDouble(struct vbob *vbob, double value)
{
  CHECK_OBJ_NOTNULL(vbob, VBOB_MAGIC);
  if (vbob->err)
    return vbob->err;
  vbob->err = VBOB_Update_cursor(vbob, VBOR_FLOAT_SIMPLE, 0);
  if (vbob->err)
    return vbob->err;
  vbob->err = VBOB_AddHeaderFloat(vbob, 8);
  if (vbob->err)
    return vbob->err;
  invert_bytes((uint8_t *)&value, 8);
  return VSB_bcat(vbob->vsb, &value, 8);
}

int
VBOB_Finish(struct vbob *vbob, struct vbor **vbor)
{
  CHECK_OBJ_NOTNULL(vbob, VBOB_MAGIC);
  if (vbob->err || VSB_finish(vbob->vsb) == -1)
    return -1;
  *vbor = VBOR_Alloc((const uint8_t*)VSB_data(vbob->vsb),
                  VSB_len(vbob->vsb), vbob->max_depth);
  CHECK_OBJ_NOTNULL(*vbor, VBOR_MAGIC);
  return 0;
}

static unsigned
is_nb_float(const char *str)
{
  while (isdigit(*str))
    str++;
  return *str == '.';
}

static const char *
get_str_end(const char *str)
{
  unsigned escaped = 0;
  while (*str != '\0')
  {
    if (!escaped && *str == '"')
      break;
    if (*str == '\\' && !escaped)
      escaped = 1;
    else
      escaped = 0;
    str++;
  }
  return *str == '"' ? str : NULL;
}

static size_t
json_count_elements(const char *json)
{
  size_t count = 0;
  char openings[] = {
    '{',
    '[',
    '"',
    '\'',
  };
  char closings[] = {
    '}',
    ']',
    '"',
    '\'',
  };

  if (*json != '{' && *json != '[')
    return -1;
  char closing = *json == '[' ? ']' : '}';
  json++;
  while (*json != '\0' && *json != closing)
  {
    unsigned sub_opening_found = 0;
    char sub_closing = 0;
    for (int i = 0; i < 4; i++)
    {
      if (*json == openings[i])
      {
        sub_opening_found = 1;
        sub_closing = closings[i];
        break;
      }
    }
    if (sub_opening_found)
    {
      json++;
      while ((*json != sub_closing) ||
        ((sub_closing == '\'' || sub_closing == '"') &&
        *json != sub_closing && *(json - 1) == '\\'))
        json++;
      if (*json == '\0')
        return -1;
    }
    if (*json == ',' || (count == 0 && !isspace(*json)))
      count++;
    json++;
  }
  if (*json == '\0')
    return -1;
  return count;
}

int
VBOB_ParseJSON(const char *json, struct vbor **vbor, unsigned max_depth)
{
  AN(json);
  AN(vbor);
  struct vbob *vbob = VBOB_Alloc(max_depth);
  int sign = 1;
  unsigned depth = 0;
  unsigned real_max_depth = 0;
  while (*json != '\0')
  {
    if (*json == ' ' || *json == '\t' || *json == '\n' || *json == ',' || *json == ':')
    {
      json++;
      continue;
    }
    switch (*json)
    {
    case '{':;
      size_t count = json_count_elements(json);
      if (count == (size_t)-1)
      {
        VBOB_Destroy(&vbob);
        return -1;
      }
      VBOB_AddMap(vbob, count);
      depth++;
      if (depth > vbob->max_depth)
      {
        VBOB_Destroy(&vbob);
        return -1;
      }
      if (depth > real_max_depth)
        real_max_depth = depth;
      json++;
      break;
    case '[':;
      count = json_count_elements(json);
      if (count == (size_t)-1)
      {
        VBOB_Destroy(&vbob);
        return -1;
      }
      VBOB_AddArray(vbob, count);
      depth++;
      if (depth > vbob->max_depth)
      {
        VBOB_Destroy(&vbob);
        return -1;
      }
      if (depth > real_max_depth)
        real_max_depth = depth;
      json++;
      break;
    case '}':
    case ']':
      depth--;
      json++;
      break;
    case '-':
      sign = -1;
      json++;
      if (!isdigit(*json))
      {
        VBOB_Destroy(&vbob);
        return -1;
      }
      break;
    case '0':
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9':;
      char *endptr = NULL;
      if (is_nb_float(json))
      {
        double dval = strtod(json, &endptr);
        json = endptr;
        VBOB_AddDouble(vbob, dval * sign);
      }
      else
      {
        uint64_t val = strtoul(json, &endptr, 10);
        json = endptr;
        if (sign == -1)
        {
          VBOB_AddNegint(vbob, val);
        }
        else
        {
          VBOB_AddUInt(vbob, val);
        }
      }
      sign = 1;
      break;
    case '"':
      json++;
      const char *end = get_str_end(json);
      if (end == NULL)
      {
        VBOB_Destroy(&vbob);
        return -1;
      }
      VBOB_AddString(vbob, json, end - json);
      json += (end - json) + 1;
      break;
    case 't':
    case 'f':
    case 'n':
      if (!memcmp(json, "true", 4)) {
        VBOB_AddBool(vbob, 1);
        json += 4;
      }
      else if (!memcmp(json, "false", 5)) {
        VBOB_AddBool(vbob, 0);
        json += 5;
      }
      else if (!memcmp(json, "null", 4)) {
        VBOB_AddNull(vbob);
        json += 4;
      }
      else {
        VBOB_Destroy(&vbob);
        return -1;
      }
      break;
    default:
      VBOB_Destroy(&vbob);
      return -1;
    }
  }
  vbob->max_depth = real_max_depth;
  int ret = VBOB_Finish(vbob, vbor);
  VBOB_Destroy(&vbob);
  return ret;
}

struct vboc *
VBOC_Alloc(struct vbor *vbor)
{
  struct vboc *vboc;
  CHECK_OBJ_NOTNULL(vbor, VBOR_MAGIC);
  ALLOC_OBJ(vboc, VBOC_MAGIC);
  vboc->src = vbor;
  vboc->current[0].magic = 0;
  return vboc;
}

enum vbor_major_type
VBOC_Next(struct vboc *vboc, struct vbor **vbor)
{
  CHECK_OBJ_NOTNULL(vboc, VBOC_MAGIC);
  enum vbor_major_type type;
  enum vbor_argument arg;
  size_t len;
  size_t skip = 1;

  *vbor = NULL;
  if (vboc->current->magic == 0)
  {
    vboc->current->magic = VBOR_MAGIC;
    if (VBOR_InitSub(vboc->src->data, vboc->src->len, vboc->src->max_depth, &vboc->current[0]) == VBOR_ERROR)
      return VBOR_ERROR;
    *vbor = vboc->current;
    return VBOR_What(vboc->current);
  }
  if (vboc->current->len <= 0)
    return VBOR_END;
  if (!VBOR_GetHeader(vboc->current, &type, &arg, &len))
    return VBOR_ERROR;
  skip += vbor_length_encoded_size(len);
  if (type == VBOR_TEXT_STRING || type == VBOR_BYTE_STRING)
    skip += len;
  if (VBOR_InitSub(vboc->current->data + skip, vboc->current->len - skip, vboc->current->max_depth, vboc->current) == -1)
    return VBOR_ERROR;
  *vbor = vboc->current;
  return VBOR_What(vboc->current);
}

void VBOC_Destroy(struct vboc **vboc)
{
  CHECK_OBJ_NOTNULL(*vboc, VBOC_MAGIC);
  FREE_OBJ(*vboc);
}

static char *json = "{\"a\": 5000000000, \"b\": [-3000, \"hello\", 256000, \"world\"], \"g\": \"goodbye\"}";
static char *json_2 = "[true, false, null, 340282.343750]";

int
main(void)
{
  struct vbob *vbob = VBOB_Alloc(10);
  CHECK_OBJ_NOTNULL(vbob, VBOB_MAGIC);

  VBOB_AddArray(vbob, 4);
  VBOB_AddUInt(vbob, 5000000000);
  VBOB_AddMap(vbob, 3);
  VBOB_AddNegint(vbob, 3000);
  VBOB_AddString(vbob, "hello", 5);
  VBOB_AddUInt(vbob, 256000);
  VBOB_AddByteString(vbob, (const uint8_t*)"world", 5);
  VBOB_AddUInt(vbob, 42);
  VBOB_AddMap(vbob, 2);
  VBOB_AddString(vbob, "a", 1);
  VBOB_AddNegint(vbob, 1000);
  VBOB_AddString(vbob, "b", 1);
  VBOB_AddArray(vbob, 3);
  VBOB_AddUInt(vbob, 1);
  VBOB_AddUInt(vbob, 2);
  VBOB_AddUInt(vbob, 3);
  VBOB_AddString(vbob, "goodbye", 7);
  VBOB_AddString(vbob, "lenin", 5);
  struct vbor *vbor = NULL;
  assert(VBOB_Finish(vbob, &vbor) == 0);
  
  VBOB_Destroy(&vbob);
  for (size_t i = 0; i < vbor->len; i++)
  {
    printf("%.2X ", vbor->data[i]);
  }
  printf("\n");

  size_t num_items = 0;
  assert(VBOR_GetArraySize(vbor, &num_items) == 0);
  assert(num_items == 4);

  struct vboc *vboc = VBOC_Alloc(vbor);
  
  struct vbor *next = NULL;
  assert(VBOC_Next(vboc, &next) == VBOR_ARRAY);

  assert(VBOC_Next(vboc, &next) == VBOR_UINT);
  size_t len = 0;

  size_t uval = 0;
  assert(VBOR_GetUInt(next, &uval) == 0);
  assert(uval == 5000000000);

  size_t num_pairs = 0;
  assert(VBOC_Next(vboc, &next) == VBOR_MAP);
  assert(VBOR_GetMapSize(next, &num_pairs) == 0);
  assert(num_pairs == 3);

  size_t nval = 0;
  assert(VBOC_Next(vboc, &next) == VBOR_NEGINT);
  assert(VBOR_GetNegint(next, &nval) == 0);
  assert(nval == 3000);

  const char *tdata = NULL;
  assert(VBOC_Next(vboc, &next) == VBOR_TEXT_STRING);
  assert(VBOR_GetString(next, &tdata, &len) == 0);
  assert(len == 5);
  assert(memcmp(tdata, "hello", 5) == 0);

  assert(VBOC_Next(vboc, &next) == VBOR_UINT);
  assert(VBOR_GetUInt(next, &uval) == 0);
  assert(uval == 256000);

  const uint8_t *bdata = NULL;
  assert(VBOC_Next(vboc, &next) == VBOR_BYTE_STRING);
  assert(VBOR_GetByteString(next, &bdata, &len) == 0);
  assert(memcmp(bdata, "world", 5) == 0);
  assert(len == 5);

  VBOC_Destroy(&vboc);

  struct vsb *vsb = VSB_new_auto();
  VBOR_PrintJSON(vbor, vsb, 1);
  VSB_finish(vsb);
  printf("%s\n", VSB_data(vsb));
  VSB_destroy(&vsb);

  VBOR_Destroy(&vbor);

  assert(json_count_elements(json) == 3);
  assert(json_count_elements(json + 23) == 4);

  assert(VBOB_ParseJSON(json, &vbor, 1) == -1);
  assert(VBOB_ParseJSON(json, &vbor, 2) != -1);
  assert(vbor->max_depth == 2);
  assert(VBOR_What(vbor) == VBOR_MAP);
  for (size_t i = 0; i < vbor->len; i++)
  {
    printf("%.2X ", vbor->data[i]);
  }
  printf("\n");
  VBOR_Destroy(&vbor);

  assert(VBOB_ParseJSON(json_2, &vbor, 1) != -1);
  for (size_t i = 0; i < vbor->len; i++)
  {
    printf("%.2X ", vbor->data[i]);
  }
  printf("\n");

  vsb = VSB_new_auto();
  assert(VBOR_PrintJSON(vbor, vsb, 0) != -1);
  VSB_finish(vsb);
  printf("%s\n", VSB_data(vsb));
  VSB_destroy(&vsb);

  VBOR_Destroy(&vbor);

  vbob = VBOB_Alloc(10);
  assert(VBOB_AddUInt(vbob, 5000000000) == 0);
  assert(VBOB_AddString(vbob, "hello", 5) == -1);

  VBOB_Destroy(&vbob);

  vbob = VBOB_Alloc(1);
  assert(VBOB_AddArray(vbob, 2) == 0);
  assert(VBOB_AddArray(vbob, 2) == -1);
  VBOB_Destroy(&vbob);

  vbob = VBOB_Alloc(1);
  assert(VBOB_AddArray(vbob, 2) == 0);
  assert(VBOB_AddUInt(vbob, 1) == 0);
  assert(VBOB_AddUInt(vbob, 2) == 0);
  assert(VBOB_AddUInt(vbob, 3) == -1);
  VBOB_Destroy(&vbob);

  vbob = VBOB_Alloc(3);
  assert(VBOB_AddMap(vbob, 3) == 0);
  assert(vbob->depth == 0);
    assert(VBOB_AddUInt(vbob, 1) == 0);
    assert(VBOB_AddArray(vbob, 2) == 0);
      assert(vbob->depth == 1);
      assert(VBOB_AddUInt(vbob, 2) == 0);
      assert(VBOB_AddUInt(vbob, 3) == 0);
    assert(VBOB_AddUInt(vbob, 4) == 0);
    assert(VBOB_AddArray(vbob, 3) == 0);
      assert(vbob->depth == 1);
      assert(VBOB_AddArray(vbob, 1) == 0);
        assert(vbob->depth == 2);
        assert(VBOB_AddString(vbob, "hello", 5) == 0);
      assert(VBOB_AddArray(vbob, 3) == 0);
        assert(vbob->depth == 2);
        assert(VBOB_AddUInt(vbob, 1) == 0);
        assert(VBOB_AddUInt(vbob, 2) == 0);
        assert(VBOB_AddUInt(vbob, 3) == 0);
      assert(VBOB_AddUInt(vbob, 4) == 0);
    assert(VBOB_AddUInt(vbob, 5) == 0);
    assert(VBOB_AddUInt(vbob, 6) == 0);
    assert(VBOB_AddUInt(vbob, 7) == -1);
  VBOB_Destroy(&vbob);

  vbob = VBOB_Alloc(3);
  assert(VBOB_AddMap(vbob, 3) == 0);
  assert(vbob->depth == 0);
  assert(VBOB_AddUInt(vbob, 1) == 0);
  assert(VBOB_AddArray(vbob, 2) == 0);
  assert(vbob->depth == 1);
  assert(VBOB_AddUInt(vbob, 2) == 0);
  assert(VBOB_AddUInt(vbob, 3) == 0);
  assert(VBOB_AddUInt(vbob, 4) == 0);
  assert(VBOB_AddArray(vbob, 3) == 0);
  assert(vbob->depth == 1);
  assert(VBOB_AddArray(vbob, 1) == 0);
  assert(vbob->depth == 2);
  assert(VBOB_AddString(vbob, "hello", 5) == 0);
  assert(VBOB_AddArray(vbob, 3) == 0);
  assert(vbob->depth == 2);
  assert(VBOB_AddUInt(vbob, 1) == 0);
  assert(VBOB_AddUInt(vbob, 2) == 0);
  assert(VBOB_AddUInt(vbob, 3) == 0);
  assert(VBOB_AddUInt(vbob, 4) == 0);
  assert(VBOB_AddUInt(vbob, 5) == 0);
  assert(VBOB_AddUInt(vbob, 6) == 0);
  assert(VBOB_AddMap(vbob, 3) == -1);
  VBOB_Destroy(&vbob);

  vbob = VBOB_Alloc(3);
  assert(VBOB_AddMap(vbob, 3) == 0);
  assert(vbob->depth == 0);
    assert(VBOB_AddUInt(vbob, 1) == 0);
    assert(VBOB_AddArray(vbob, 2) == 0);
      assert(vbob->depth == 1);
      assert(VBOB_AddUInt(vbob, 2) == 0);
      assert(VBOB_AddUInt(vbob, 3) == 0);
    assert(VBOB_AddUInt(vbob, 4) == 0);
    assert(VBOB_AddArray(vbob, 3) == 0);
      assert(vbob->depth == 1);
      assert(VBOB_AddArray(vbob, 1) == 0);
        assert(vbob->depth == 2);
        assert(VBOB_AddString(vbob, "hello", 5) == 0);
      assert(VBOB_AddArray(vbob, 3) == 0);
        assert(vbob->depth == 2);
        assert(VBOB_AddUInt(vbob, 1) == 0);
        assert(VBOB_AddUInt(vbob, 2) == 0);
        assert(VBOB_AddUInt(vbob, 3) == 0);
      assert(VBOB_AddUInt(vbob, 4) == 0);
    assert(VBOB_AddUInt(vbob, 5) == 0);
    assert(VBOB_AddUInt(vbob, 6) == 0);
  assert(VBOB_Finish(vbob, &vbor) == 0);
  VBOB_Destroy(&vbob);

  vsb = VSB_new_auto();
  assert(VBOR_PrintJSON(vbor, vsb, 1) != -1);
  VSB_finish(vsb);
  printf("%s\n", VSB_data(vsb));
  VSB_destroy(&vsb);

  VBOR_Destroy(&vbor);

  vbob = VBOB_Alloc(1);
  assert(VBOB_AddArray(vbob, 8) == 0);
  assert(VBOB_AddFloat(vbob, 3.4028234663852886e+5) == 0);
  assert(VBOB_AddDouble(vbob, -4.1) == 0);
  assert(VBOB_AddSimple(vbob, 8) == 0);
  assert(VBOB_AddSimple(vbob, 135) == 0);
  assert(VBOB_AddBool(vbob, 1) == 0);
  assert(VBOB_AddBool(vbob, 0) == 0);
  assert(VBOB_AddNull(vbob) == 0);
  assert(VBOB_AddUndefined(vbob) == 0);
  assert(VBOB_Finish(vbob, &vbor) == 0);
  VBOB_Destroy(&vbob);
  for (size_t i = 0; i < vbor->len; i++)
  {
    printf("%.2X ", vbor->data[i]);
  }
  printf("\n");
  vsb = VSB_new_auto();
  assert(VBOR_PrintJSON(vbor, vsb, 1) != -1);
  VSB_finish(vsb);
  printf("%s\n", VSB_data(vsb));
  VSB_destroy(&vsb);
  VBOR_Destroy(&vbor);

  vbob = VBOB_Alloc(1);
  assert(VBOB_AddTag(vbob, 55799) == 0); // Magic number for CBOR
  assert(VBOB_AddArray(vbob, 3) == 0);
  assert(VBOB_AddTag(vbob, 2) == 0);
  assert(VBOB_AddString(vbob, "hello", 5) == 0);
  assert(VBOB_AddTag(vbob, 42) == 0);
  assert(VBOB_AddString(vbob, "world", 5) == 0);
  assert(VBOB_AddTag(vbob, 6500) == 0);
  assert(VBOB_AddString(vbob, "foo", 3) == 0);
  assert(VBOB_Finish(vbob, &vbor) == 0);
  VBOB_Destroy(&vbob);
  for (size_t i = 0; i < vbor->len; i++)
  {
    printf("%.2X ", vbor->data[i]);
  }
  printf("\n");
  vsb = VSB_new_auto();
  assert(VBOR_PrintJSON(vbor, vsb, 1) != -1);
  VSB_finish(vsb);
  printf("%s\n", VSB_data(vsb));
  VSB_destroy(&vsb);
  VBOR_Destroy(&vbor);

  return EXIT_SUCCESS;
}