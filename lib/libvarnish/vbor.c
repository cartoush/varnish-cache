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
  enum vbor_argument arg = VBOR_ARG_5BITS;
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
vbor_encode_type(enum vbor_major_type type)
{
  return type << 5;
}

static enum vbor_major_type
vbor_decode_type(uint8_t data)
{
  enum vbor_major_type type = data >> 5;

  if (type < VBOR_UINT || type > VBOR_MAP)
  {
    type = VBOR_UNKNOWN;
  }
  return type;
}

static enum vbor_argument
vbor_decode_arg(uint8_t data)
{
  enum vbor_argument arg = data & 0b00011111;

  if (arg > 0x1b)
  {
    arg = VBOR_ARG_UNKNOWN;
  }
  else if (arg < 0x18)
  {
    arg = VBOR_ARG_5BITS;
  }
  else
  {
    arg = arg - 0x17;
  }
  return arg;
}

static size_t
vbor_decode_value_length(enum vbor_major_type type, enum vbor_argument arg, const uint8_t *data, size_t length)
{
  size_t len = 0;
  if (type == VBOR_UNKNOWN || arg == VBOR_ARG_UNKNOWN)
  {
    return -1;
  }
  else if (arg == VBOR_ARG_5BITS)
  {
    len = (*data) & 0b00011111;
  }
  else
  {
    uint8_t len_len = pow(2, arg - 1);
    if (len_len > length - 1)
    {
      return -1;
    }
    for (size_t i = 0; i < len_len; i++)
    {
      len <<= 8;
      len += data[1 + i];
    }
  }
  return len;
}

struct vbor *
VBOR_Init(const uint8_t *data, size_t len, unsigned max_depth)
{
  struct vbor *vbor;
  AN(data);
  AN(len);
  ALLOC_OBJ(vbor, VBOR_MAGIC);
  vbor->data = malloc(len);
  AN(vbor->data);
  memcpy((void*)vbor->data, data, len);
  vbor->len = len;
  vbor->sub = false;
  vbor->max_depth = max_depth;
  return vbor;
}

struct vbor *
VBOR_InitSub(const uint8_t *data, size_t len, unsigned super_depth)
{
  struct vbor *vbor;
  AN(data);
  if (len == 0)
  {
    return NULL;
  }
  ALLOC_OBJ(vbor, VBOR_MAGIC);
  vbor->data = data;
  vbor->len = len;
  vbor->sub = true;
  switch (VBOR_What(vbor)) {
  case VBOR_ARRAY:
  case VBOR_MAP:
    vbor->max_depth = super_depth - 1;
    break;
  default:
    vbor->max_depth = super_depth;
    break;
  }
  return vbor;
}

int
VBOR_PrintJSON(struct vbor *vbor, struct vsb *json, bool pretty)
{
  CHECK_OBJ_NOTNULL(vbor, VBOR_MAGIC);
  CHECK_OBJ_NOTNULL(json, VSB_MAGIC);
  struct vboc *vboc = VBOC_Init(vbor);
  size_t idxs[vbor->max_depth];
  enum vbor_major_type types[vbor->max_depth];
  size_t depth = -1;
  size_t initial_len = VSB_len(json);

  struct vbor *next = vbor;
  do {
    if (pretty && depth != (size_t)-1 && !(types[depth] == VBOR_MAP && idxs[depth] % 2 == 1))
    {
      for (size_t i = 0; i < depth + 1; i++)
        VSB_putc(json, '\t');
    }
    enum vbor_major_type type = VBOR_What(next);
    switch (type)
    {
    case VBOR_UINT:
      VSB_printf(json, "%lu", VBOR_GetUInt(next));
      break;
    case VBOR_NEGINT:
      VSB_printf(json, "-%lu", VBOR_GetNegint(next));
      break;
    case VBOR_TEXT_STRING:;
      size_t data_len = 0;
      const uint8_t *data = (const uint8_t*)VBOR_GetString(next, &data_len);
      VSB_putc(json, '"');
      VSB_bcat(json, data, data_len);
      VSB_putc(json, '"');
      break;
    case VBOR_BYTE_STRING:
      data = VBOR_GetByteString(next, &data_len);
      VSB_putc(json, '"');
      VENC_Encode_Base64(json, data, data_len);
      VSB_putc(json, '"');
      break;
    case VBOR_ARRAY:
      VSB_printf(json, "[");
      depth++;
      idxs[depth] = VBOR_GetArraySize(next);
      types[depth] = VBOR_ARRAY;
      break;
    case VBOR_MAP:
      VSB_printf(json, "{");
      depth++;
      idxs[depth] = VBOR_GetMapSize(next) * 2;
      types[depth] = VBOR_MAP;
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
    {
      VSB_putc(json, '\n');
    }
  } while ((next = VBOC_Next(vboc)) != NULL);
  VBOC_Destroy(&vboc);
  return VSB_len(json) - initial_len;
}

void
VBOR_Destroy(struct vbor **vbor)
{
  CHECK_OBJ_NOTNULL(*vbor, VBOR_MAGIC);
  if (!(*vbor)->sub)
  {
    AN((*vbor)->data);
    free((void*)(*vbor)->data);
  }
  FREE_OBJ(*vbor);
}

static bool
VBOR_GetHeader(const struct vbor *vbor, enum vbor_major_type *type, enum vbor_argument *arg, size_t *len)
{
  CHECK_OBJ_NOTNULL(vbor, VBOR_MAGIC);
  AN(type);
  AN(arg);
  AN(len);
  *type = vbor_decode_type(vbor->data[0]);
  if (*type == VBOR_UNKNOWN)
  {
    return false;
  }
  *arg = vbor_decode_arg(vbor->data[0]);
  if (*arg == VBOR_ARG_UNKNOWN)
  {
    return false;
  }
  *len = vbor_decode_value_length(*type, *arg, vbor->data, vbor->len);
  if (*len == (size_t)-1)
  {
    return false;
  }
  return true;
}

uint64_t
VBOR_GetUInt(const struct vbor *vbor)
{
  CHECK_OBJ_NOTNULL(vbor, VBOR_MAGIC);
  enum vbor_major_type type = VBOR_UNKNOWN;
  enum vbor_argument arg = VBOR_ARG_UNKNOWN;
  size_t len = - 1;
  if (!VBOR_GetHeader(vbor, &type, &arg, &len))
  {
    return -1;
  }
  if (type != VBOR_UINT)
  {
    return -1;
  }
  return len;
}

uint64_t
VBOR_GetNegint(const struct vbor *vbor)
{
  CHECK_OBJ_NOTNULL(vbor, VBOR_MAGIC);
  enum vbor_major_type type = VBOR_UNKNOWN;
  enum vbor_argument arg = VBOR_ARG_UNKNOWN;
  size_t len = - 1;
  if (!VBOR_GetHeader(vbor, &type, &arg, &len))
  {
    return -1;
  }
  if (type != VBOR_NEGINT)
  {
    return -1;
  }
  return len + 1;
}

const char *
VBOR_GetString(const struct vbor *vbor, size_t *len)
{
  CHECK_OBJ_NOTNULL(vbor, VBOR_MAGIC);
  AN(len);
  enum vbor_major_type type = VBOR_UNKNOWN;
  enum vbor_argument arg = VBOR_ARG_UNKNOWN;
  *len = -1;
  if (!VBOR_GetHeader(vbor, &type, &arg, len))
  {
    return NULL;
  }
  if (type != VBOR_TEXT_STRING)
  {
    return NULL;
  }
  return (const char*)vbor->data + 1 + vbor_length_encoded_size(*len);
}

const uint8_t *
VBOR_GetByteString(const struct vbor *vbor, size_t *len)
{
  CHECK_OBJ_NOTNULL(vbor, VBOR_MAGIC);
  AN(len);
  enum vbor_major_type type = VBOR_UNKNOWN;
  enum vbor_argument arg = VBOR_ARG_UNKNOWN;
  *len = - 1;
  if (!VBOR_GetHeader(vbor, &type, &arg, len))
  {
    return NULL;
  }
  if (type != VBOR_BYTE_STRING)
  {
    return NULL;
  }
  return vbor->data + 1 + vbor_length_encoded_size(*len);
}

size_t VBOR_GetArraySize(const struct vbor *vbor)
{
  CHECK_OBJ_NOTNULL(vbor, VBOR_MAGIC);
  enum vbor_major_type type = VBOR_UNKNOWN;
  enum vbor_argument arg = VBOR_ARG_UNKNOWN;
  size_t len = -1;
  if (!VBOR_GetHeader(vbor, &type, &arg, &len))
  {
    return -1;
  }
  if (type != VBOR_ARRAY)
  {
    return -1;
  }
  return len;
}

size_t VBOR_GetMapSize(const struct vbor *vbor)
{
  CHECK_OBJ_NOTNULL(vbor, VBOR_MAGIC);
  enum vbor_major_type type = VBOR_UNKNOWN;
  enum vbor_argument arg = VBOR_ARG_UNKNOWN;
  size_t len = -1;
  if (!VBOR_GetHeader(vbor, &type, &arg, &len))
  {
    return -1;
  }
  if (type != VBOR_MAP)
  {
    return -1;
  }
  return len;
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
  ALLOC_OBJ(vbob, VBOB_MAGIC);
  vbob->vsb = VSB_new_auto();
  vbob->max_depth = max_depth;
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
  struct vbor *vbor = VBOR_Init((const uint8_t*)VSB_data(vbob->vsb),
                                VSB_len(vbob->vsb), vbob->max_depth);
  CHECK_OBJ_NOTNULL(vbor, VBOR_MAGIC);
  return vbor;
}

static bool
is_nb_float(const char *str)
{
  while (isdigit(*str))
    str++;
  return *str == '.';
}

static const char *
get_str_end(const char *str)
{
  bool escaped = false;
  while (*str != '\0')
  {
    if (!escaped && *str == '"')
      break;
    if (*str == '\\' && !escaped)
      escaped = true;
    else
      escaped = false;
    str++;
  }
  return *str == '"' ? str : NULL;
}

static struct vboc_pos *
VBOC_POS_Init(size_t pos)
{
  struct vboc_pos *vbocpos;
  ALLOC_OBJ(vbocpos, VBOC_POS_MAGIC);
  vbocpos->pos = pos;
  return vbocpos;
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
    bool sub_opening_found = false;
    char sub_closing = 0;
    for (int i = 0; i < 4; i++)
    {
      if (*json == openings[i])
      {
        sub_opening_found = true;
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

struct vbor *
VBOB_ParseJSON(const char *json)
{
  AN(json);
  struct vbob *vbob = VBOB_Alloc(0);
  int sign = 1;
  unsigned depth = 0;
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
        return NULL;
      VBOB_AddMap(vbob, count);
      depth++;
      if (depth > vbob->max_depth)
        vbob->max_depth = depth;
      json++;
      break;
    case '}':
      depth--;
      json++;
      break;
    case '[':;
      count = json_count_elements(json);
      if (count == (size_t)-1)
        return NULL;
      VBOB_AddArray(vbob, count);
      depth++;
      if (depth > vbob->max_depth)
        vbob->max_depth = depth;
      json++;
      break;
    case ']':
      depth--;
      json++;
      break;
    case '-':
      sign = -1;
      json++;
      if (!isdigit(*json))
      {
        return NULL;
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
    case '9':
      if (is_nb_float(json))
      {
        xxxassert("TODO handle float");
        while (isdigit(*json))
        {
          json++;
        }
        json++;
        while (isdigit(*json))
        {
          json++;
        }
      }
      else
      {
        uint64_t val = strtoul(json, NULL, 10);
        if (sign == -1)
        {
          VBOB_AddNegint(vbob, val);
        }
        else
        {
          VBOB_AddUInt(vbob, val);
        }
      }
      while (isdigit(*json))
      {
        json++;
      }
      sign = 1;
      break;
    case '"':
      json++;
      const char *end = get_str_end(json);
      VBOB_AddString(vbob, json, end - json);
      json += (end - json) + 1;
      break;
    default:
      return NULL;
    }
  }
  struct vbor *vbor = VBOB_Finish(vbob);
  VBOB_Destroy(&vbob);
  return vbor;
}

struct vboc *
VBOC_Init(struct vbor *vbor)
{
  struct vboc *vboc;
  CHECK_OBJ_NOTNULL(vbor, VBOR_MAGIC);
  ALLOC_OBJ_EXTRA(vboc, sizeof(struct vboc_pos) * vbor->max_depth, VBOC_MAGIC);
  vboc->src = vbor;
  vboc->current = vbor;
  vboc->depth = -1;
  vboc->max_depth = vbor->max_depth;
  for (unsigned i = 0; i < vboc->max_depth; i++) {
    vboc->pos[i].magic = VBOC_POS_MAGIC;
    vboc->pos[i].pos = -1;
    vboc->pos[i].len = 0;
  }
  vboc->pos[0].pos = 0;
  return vboc;
}

static void
VBOC_Update_cursor(struct vboc *vboc)
{
  enum vbor_major_type type = VBOR_What(vboc->current);

  if (type != VBOR_ARRAY && type != VBOR_MAP)
  {
    if (vboc->depth == (unsigned)-1)
      return;
    else
      vboc->pos[vboc->depth].pos += 1;
  }
  if (type == VBOR_ARRAY || type == VBOR_MAP)
  {
    vboc->depth++;
    assert(vboc->depth <= vboc->max_depth);
    vboc->pos[vboc->depth].len = type == VBOR_ARRAY ? VBOR_GetArraySize(vboc->current) : VBOR_GetMapSize(vboc->current) * 2;
    vboc->pos[vboc->depth].pos = 0;
  }

  if (vboc->depth != 0 && vboc->pos[vboc->depth].pos >= vboc->pos[vboc->depth].len)
  {
    while (vboc->depth != (unsigned)-1 && vboc->pos[vboc->depth].pos >= vboc->pos[vboc->depth].len)
    {
      vboc->depth--;
      vboc->pos[vboc->depth].pos += 1;
    }
  }
}

struct vbor *
VBOC_Next(struct vboc *vboc)
{
  CHECK_OBJ_NOTNULL(vboc, VBOC_MAGIC);
  enum vbor_major_type type;
  enum vbor_argument arg;
  size_t len;
  size_t skip = 1;

  VBOC_Update_cursor(vboc);
  if (!VBOR_GetHeader(vboc->current, &type, &arg, &len))
  {
    return NULL;
  }
  skip += vbor_length_encoded_size(len);
  if (type == VBOR_TEXT_STRING || type == VBOR_BYTE_STRING)
  {
    skip += len;
  }
  struct vbor *tmp = VBOR_InitSub(vboc->current->data + skip, vboc->current->len - skip, vboc->current->max_depth);
  if (vboc->current != vboc->src)
  {
    VBOR_Destroy(&vboc->current);
  }
  vboc->current = tmp;
  return vboc->current;
}

struct vboc_pos *
VBOC_Where(struct vboc *vboc, size_t *depth)
{
  CHECK_OBJ_NOTNULL(vboc, VBOC_MAGIC);
  AN(depth);
  *depth = vboc->depth + 1;
  return vboc->pos;
}

void VBOC_Destroy(struct vboc **vboc)
{
  CHECK_OBJ_NOTNULL(*vboc, VBOC_MAGIC);
  FREE_OBJ(*vboc);
}

// static uint8_t cbor[] = {
//     0x83, 0x1B, 0x00, 0x00, 0x00, 0x01, 0x2A, 0x05, 0xF2, 0x00, 0xA2, 0x39, 0x0B, 0xB7, 0x65, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x1A, 0x00, 0x03, 0xE8, 0x00, 0x45, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x67, 0x67, 0x6F, 0x6F, 0x64, 0x62, 0x79, 0x65
// };

static char *json = "{\"a\": 5000000000, \"b\": [-3000, \"hello\", 256000, \"world\"], \"g\": \"goodbye\"}";

int
main(void)
{
  struct vbob *vbob = VBOB_Alloc(10);

  VBOB_AddArray(vbob, 4);
  VBOB_AddUInt(vbob, 5000000000);
  VBOB_AddMap(vbob, 3);
  VBOB_AddNegint(vbob, 3000);
  VBOB_AddString(vbob, "hello", 5);
  VBOB_AddUInt(vbob, 256000);
  VBOB_AddByteString(vbob, "world", 5);
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
  struct vbor *vbor = VBOB_Finish(vbob);
  VBOB_Destroy(&vbob);
  for (size_t i = 0; i < vbor->len; i++)
  {
    printf("%.2X ", vbor->data[i]);
  }
  printf("\n");
  
  assert(VBOR_GetArraySize(vbor) == 4);

  struct vboc *vboc = VBOC_Init(vbor);
  struct vbor *next = VBOC_Next(vboc);
  size_t len = 0;
  const uint8_t *data = NULL;
  assert(VBOR_GetUInt(next) == 5000000000);

  next = VBOC_Next(vboc);
  assert(VBOR_GetMapSize(next) == 3);

  next = VBOC_Next(vboc);
  assert(VBOR_GetNegint(next) == 3000);

  next = VBOC_Next(vboc);
  data = VBOR_GetString(next, &len);
  assert(len == 5);
  assert(memcmp(data, "hello", 5) == 0);

  next = VBOC_Next(vboc);
  assert(VBOR_GetUInt(next) == 256000);

  next = VBOC_Next(vboc);
  data = VBOR_GetByteString(next, &len);
  assert(memcmp(data, "world", 5) == 0);
  assert(len == 5);

  VBOC_Destroy(&vboc);

  vboc = VBOC_Init(vbor);
  do {
    struct vboc_pos *pos = VBOC_Where(vboc, &len);
    if (pos != NULL)
    {
      printf("where : ");
      for (size_t i = 0; i < len; i++)
      {
        printf("%ld/%ld ", pos[i].pos, pos[i].len);
      }
      printf("\n");
    }
  } while ((next = VBOC_Next(vboc)) != NULL);

  struct vsb *vsb = VSB_new_auto();
  VBOR_PrintJSON(vbor, vsb, true);
  VSB_finish(vsb);
  printf("%s\n", VSB_data(vsb));
  VSB_destroy(&vsb);

  VBOR_Destroy(&vbor);

  assert(json_count_elements(json) == 3);
  assert(json_count_elements(json + 23) == 4);

  vbor = VBOB_ParseJSON(json);
  assert(vbor->max_depth == 2);
  assert(VBOR_What(vbor) == VBOR_MAP);
  for (size_t i = 0; i < vbor->len; i++)
  {
    printf("%.2X ", vbor->data[i]);
  }
  printf("\n");
  VBOR_Destroy(&vbor);

  return EXIT_SUCCESS;
}