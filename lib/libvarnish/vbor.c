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
#include <string.h>

#include "vdef.h"

#include "miniobj.h"
#include "vas.h"
#include "vbor.h"
#include "vsb.h"

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

	for (uint8_t i = 0; i < len / 2; i++) {
		tmp = val[i];
		val[i] = val[len - i - 1];
		val[len - i - 1] = tmp;
	}
}

static uint8_t
VBOR_LengthEncodedSize(size_t size)
{

	if (size > 0xFFFFFFFF)
		return (8);
	if (size > 0xFFFF)
		return (4);
	if (size > 0xFF)
		return (2);
	if (size > 23)
		return (1);
	return (0);
}

static enum vbor_type
VBOR_DecodeType(uint8_t data)
{
	enum vbor_type type = data >> 5;

	if (type != VBOR_FLOAT_SIMPLE)
		return (type);
	if (data >= (VBOR_FLOAT_SIMPLE << 5) + 28)
		return (VBOR_ERROR);
	switch (data) {
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
	return (type);
}

static enum vbor_argument
VBOR_DecodeArg(uint8_t data)
{
	enum vbor_argument arg = data & 0b00011111;

	if (arg > 0x1b)
		arg = VBOR_ARG_UNKNOWN;
	else if (arg < 0x18)
		arg = VBOR_ARG_5BITS;
	else
		arg = arg - 0x17;
	return (arg);
}

static size_t
VBOR_DecodeValueLength(enum vbor_type type, enum vbor_argument arg,
	    const uint8_t *data, size_t length)
{
	size_t len = 0;

	if (type == VBOR_UNKNOWN || arg == VBOR_ARG_UNKNOWN)
		return (-1);
	else if (arg == VBOR_ARG_5BITS)
		len = (*data) & 0b00011111;
	else {
		uint8_t len_len = pow(2, arg - 1);
		if (len_len > length - 1)
			return (-1);
		for (size_t i = 0; i < len_len; i++) {
			len <<= 8;
			len += data[1 + i];
		}
	}
	return (len);
}

static int
VBOR_GetTypeArg(const struct vbor *vbor, enum vbor_type *type,
	    enum vbor_argument *arg)
{

	CHECK_OBJ_NOTNULL(vbor, VBOR_MAGIC);
	AN(type);
	AN(arg);
	*type = VBOR_DecodeType(vbor->data[0]);
	if (*type == VBOR_UNKNOWN)
		return (-1);
	*arg = VBOR_DecodeArg(vbor->data[0]);
	if (*arg == VBOR_ARG_UNKNOWN)
		return (-1);
	return (0);
}

static int
VBOR_GetHeader(const struct vbor *vbor, enum vbor_type *type,
	    enum vbor_argument *arg, size_t *len)
{

	CHECK_OBJ_NOTNULL(vbor, VBOR_MAGIC);
	AN(type);
	AN(arg);
	AN(len);
	if (VBOR_GetTypeArg(vbor, type, arg))
		return (-1);
	*len = VBOR_DecodeValueLength(*type, *arg, vbor->data, vbor->len);
	if (*len == (size_t)-1)
		return (-1);
	return (0);
}

int
VBOR_Init(struct vbor *vbor, const uint8_t *data, size_t len,
	    unsigned max_depth)
{

	AN(vbor);
	AN(data);
	if (len == 0)
		return (-1);
	vbor->magic = VBOR_MAGIC;
	vbor->data = data;
	vbor->len = len;
	vbor->max_depth = max_depth;
	return (0);
}

int
VBOR_Copy(struct vbor *dst, const struct vbor *src)
{

	CHECK_OBJ_NOTNULL(src, VBOR_MAGIC);
	return (VBOR_Init(dst, src->data, src->len, src->max_depth));
}

void
VBOR_Fini(struct vbor *vbor)
{

	CHECK_OBJ_NOTNULL(vbor, VBOR_MAGIC);
	FINI_OBJ(vbor);
}

int
VBOR_GetUInt(const struct vbor *vbor, uint64_t *res)
{
	enum vbor_type type = VBOR_UNKNOWN;
	enum vbor_argument arg = VBOR_ARG_UNKNOWN;
	size_t len = -1;

	CHECK_OBJ_NOTNULL(vbor, VBOR_MAGIC);
	AN(res);
	if (VBOR_GetHeader(vbor, &type, &arg, &len))
		return (-1);
	if (type != VBOR_UINT)
		return (-1);
	*res = len;
	return (0);
}

int
VBOR_GetNegint(const struct vbor *vbor, uint64_t *res)
{
	enum vbor_type type = VBOR_UNKNOWN;
	enum vbor_argument arg = VBOR_ARG_UNKNOWN;
	size_t len = -1;

	CHECK_OBJ_NOTNULL(vbor, VBOR_MAGIC);
	AN(res);
	if (VBOR_GetHeader(vbor, &type, &arg, &len))
		return (-1);
	if (type != VBOR_NEGINT)
		return (-1);
	*res = len + 1;
	return (0);
}

int
VBOR_GetString(const struct vbor *vbor, const char **res, size_t *len)
{
	enum vbor_type type = VBOR_UNKNOWN;
	enum vbor_argument arg = VBOR_ARG_UNKNOWN;

	CHECK_OBJ_NOTNULL(vbor, VBOR_MAGIC);
	AN(len);
	*len = -1;
	if (VBOR_GetHeader(vbor, &type, &arg, len))
		return (-1);
	if (type != VBOR_TEXT_STRING)
		return (-1);
	*res = (const char *)vbor->data + 1 + VBOR_LengthEncodedSize(*len);
	return (0);
}

int
VBOR_GetByteString(const struct vbor *vbor, const uint8_t **res, size_t *len)
{
	enum vbor_type type = VBOR_UNKNOWN;
	enum vbor_argument arg = VBOR_ARG_UNKNOWN;

	CHECK_OBJ_NOTNULL(vbor, VBOR_MAGIC);
	AN(len);
	*len = -1;
	if (VBOR_GetHeader(vbor, &type, &arg, len))
		return (-1);
	if (type != VBOR_BYTE_STRING)
		return (-1);
	*res = vbor->data + 1 + VBOR_LengthEncodedSize(*len);
	return (0);
}

int
VBOR_GetArraySize(const struct vbor *vbor, size_t *len)
{
	enum vbor_type type = VBOR_UNKNOWN;
	enum vbor_argument arg = VBOR_ARG_UNKNOWN;

	CHECK_OBJ_NOTNULL(vbor, VBOR_MAGIC);
	AN(len);
	if (VBOR_GetHeader(vbor, &type, &arg, len))
		return (-1);
	if (type != VBOR_ARRAY)
		return (-1);
	return (0);
}

int
VBOR_GetMapSize(const struct vbor *vbor, size_t *len)
{
	enum vbor_type type = VBOR_UNKNOWN;
	enum vbor_argument arg = VBOR_ARG_UNKNOWN;

	CHECK_OBJ_NOTNULL(vbor, VBOR_MAGIC);
	AN(len);
	if (VBOR_GetHeader(vbor, &type, &arg, len))
		return (-1);
	if (type != VBOR_MAP)
		return (-1);
	return (0);
}

int
VBOR_GetTag(const struct vbor *vbor, uint64_t *res)
{
	enum vbor_type type = VBOR_UNKNOWN;
	enum vbor_argument arg = VBOR_ARG_UNKNOWN;
	size_t len = -1;

	CHECK_OBJ_NOTNULL(vbor, VBOR_MAGIC);
	AN(res);
	if (VBOR_GetHeader(vbor, &type, &arg, &len))
		return (-1);
	if (type != VBOR_TAG)
		return (-1);
	*res = len;
	return (0);
}

int
VBOR_GetSimple(const struct vbor *vbor, uint8_t *res)
{
	enum vbor_type type = VBOR_UNKNOWN;
	enum vbor_argument arg = VBOR_ARG_UNKNOWN;

	CHECK_OBJ_NOTNULL(vbor, VBOR_MAGIC);
	AN(res);
	if (VBOR_GetTypeArg(vbor, &type, &arg))
		return (-1);
	if (type != VBOR_SIMPLE)
		return (-1);
	if (arg == VBOR_ARG_5BITS)
		*res = vbor->data[0] & 0b00011111;
	else if (arg == VBOR_ARG_1BYTE)
		*res = vbor->data[1];
	else
		return (-1);
	if (*res >= 24 && *res < 32)
		return (-1);
	return (0);
}

int
VBOR_GetFloat(const struct vbor *vbor, float *res)
{
	enum vbor_type type = VBOR_UNKNOWN;
	enum vbor_argument arg = VBOR_ARG_UNKNOWN;

	CHECK_OBJ_NOTNULL(vbor, VBOR_MAGIC);
	AN(res);
	if (VBOR_GetTypeArg(vbor, &type, &arg))
		return (-1);
	if (type != VBOR_FLOAT)
		return (-1);
	if (arg != VBOR_ARG_4BYTES)
		return (-1);
	memcpy(res, vbor->data + 1, 4);
	invert_bytes((uint8_t *)res, 4);
	return (0);
}

int
VBOR_GetDouble(const struct vbor *vbor, double *res)
{
	enum vbor_type type = VBOR_UNKNOWN;
	enum vbor_argument arg = VBOR_ARG_UNKNOWN;

	CHECK_OBJ_NOTNULL(vbor, VBOR_MAGIC);
	AN(res);
	if (VBOR_GetTypeArg(vbor, &type, &arg))
		return (-1);
	if (type != VBOR_DOUBLE)
		return (-1);
	if (arg != VBOR_ARG_8BYTES)
		return (-1);
	memcpy(res, vbor->data + 1, 8);
	invert_bytes((uint8_t *)res, 8);
	return (0);
}

int
VBOR_GetBool(const struct vbor *vbor, unsigned *res)
{
	CHECK_OBJ_NOTNULL(vbor, VBOR_MAGIC);
	AN(res);
	if (vbor->data[0] != 0xF4 && vbor->data[0] != 0xF5)
		return (-1);
	*res = vbor->data[0] == 0xF5 ? 1 : 0;
	return (0);
}

enum vbor_type
VBOR_What(const struct vbor *vbor)
{

	CHECK_OBJ_NOTNULL(vbor, VBOR_MAGIC);
	AN(vbor->data);
	if (vbor->len == 0)
		return (VBOR_END);
	return (VBOR_DecodeType(vbor->data[0]));
}

int
VBOR_GetByteSize(const struct vbor *vbor, size_t *len)
{
	size_t acc = 1;
	enum vbor_type type;
	enum vbor_argument arg;
	struct vboc vboc;
	struct vbor next;
	size_t val_len;

	CHECK_OBJ_NOTNULL(vbor, VBOR_MAGIC);
	AN(len);
	if (VBOR_GetHeader(vbor, &type, &arg, &val_len))
		return (-1);
	if (arg != VBOR_ARG_5BITS)
		acc += pow(2, arg - 1);
	if (type == VBOR_TEXT_STRING || type == VBOR_BYTE_STRING) {
		*len = acc + val_len;
		return (0);
	}
	if (type != VBOR_ARRAY && type != VBOR_MAP) {
		*len = acc;
		return (0);
	}
	*len = val_len;
	if (type == VBOR_MAP)
		*len *= 2;
	assert(!VBOR_Init(&next, vbor->data + acc, vbor->len - acc,
	    vbor->max_depth - 1));
	VBOC_Init(&vboc, &next);

	for (size_t ctr = 0; ctr < *len; ctr++)
	{
		assert(VBOC_Next(&vboc, &next) < VBOR_END);
		if (VBOR_What(&next) == VBOR_TAG)
			ctr--;
		if (VBOR_GetByteSize(&next, &val_len))
			return (-1);
		acc += val_len;
	}
	*len = acc;
	VBOC_Fini(&vboc);
	return (0);
}

int
VBOR_Inside(const struct vbor *vbor, struct vbor *inside)
{
	enum vbor_type type = VBOR_ERROR;
	enum vbor_argument arg = VBOR_ARG_UNKNOWN;
	size_t skip = -1;
	size_t len = -1;

	CHECK_OBJ_NOTNULL(vbor, VBOR_MAGIC);
	AN(inside);
	if (VBOR_GetHeader(vbor, &type, &arg, &skip))
		return (-1);
	if (type != VBOR_ARRAY && type != VBOR_MAP)
		return (-1);
	skip = VBOR_LengthEncodedSize(skip) + 1;
	if (VBOR_GetByteSize(vbor, &len))
		return (-1);
	if (VBOR_Init(inside, vbor->data + skip, len - skip, vbor->max_depth - 1))
		return (-1);
	return (0);
}

struct vbob_pos {
	size_t	pos;
	size_t	len;
};

struct vbob {
	unsigned	magic;
#define VBOB_MAGIC	0x3abff812
	const char	*err;
	struct vsb	*vsb;
	unsigned	max_depth;
	unsigned	depth;
	struct vbob_pos	pos[];
};

static const char *vsb_not_empty_err = "VSB not empty";
static const char *index_oob_err = "Index out of bound";
static const char *max_depth_reached_err = "Max depth reached";
static const char *invalid_simple_value_err = "Invalid simple value";
static const char *half_prec_float_no_support_err =
	    "Half-precision floating number not supported";
static const char *invalid_float_size_err = "Invalid float size";
static const char *json_closing_err = "Closing character missing";
static const char *json_bad_number_err = "Bad number";
static const char *json_unterminated_str_err = "Unterminated string";
static const char *json_unrecognized_val_err = "Unrecognized value";

static int
VBOB_Update_cursor(struct vbob *vbob, enum vbor_type type, size_t len)
{

	if (type != VBOR_ARRAY && type != VBOR_MAP) {
		if (vbob->depth == (unsigned)-1) {
			if (VSB_len(vbob->vsb) != 0) {
				vbob->err = vsb_not_empty_err;
				return (-1);
			}
			return (0);
		}
		else if (type != VBOR_TAG)
			vbob->pos[vbob->depth].pos += 1;
	}
	else {
		if (vbob->depth == (unsigned)-1 && vbob->pos[0].len != 0
		    && vbob->pos[0].pos >= vbob->pos[0].len) {
			vbob->err = index_oob_err;
			return (-1);
		}
		vbob->depth++;
		if (vbob->depth >= vbob->max_depth) {
			vbob->err = max_depth_reached_err;
			return (-1);
		}
		vbob->pos[vbob->depth].len = type == VBOR_ARRAY ? len : len * 2;
		vbob->pos[vbob->depth].pos = 0;
	}
	if (vbob->depth != (unsigned)-1
	    && vbob->pos[vbob->depth].pos >= vbob->pos[vbob->depth].len) {
		while (vbob->depth != (unsigned)-1
		    && vbob->pos[vbob->depth].pos >= vbob->pos[vbob->depth].len) {
			vbob->depth--;
			if (vbob->depth != (unsigned)-1)
				vbob->pos[vbob->depth].pos += 1;
		}
		if (vbob->depth == (unsigned)-1 && vbob->pos[0].pos != 0
		    && vbob->pos[0].pos > vbob->pos[0].len) {
			vbob->err = index_oob_err;
			return (-1);
		}
	}
	return (0);
}

static uint8_t
VBOB_EncodedArg(size_t size)
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
	return (arg + 0x17);
}

static uint8_t
VBOB_EncodeType(enum vbor_type type)
{

	if (type > VBOR_FLOAT_SIMPLE && type < VBOR_END)
		type = VBOR_FLOAT_SIMPLE;
	return (type << 5);
}

static int
VBOB_AddHeader(struct vbob *vbob, enum vbor_type type, size_t len)
{
	uint8_t hdr[9] = {0};
	uint8_t written = 1;
	hdr[0] = VBOB_EncodeType(type);
	hdr[0] |= VBOB_EncodedArg(len);
	size_t size_len = VBOR_LengthEncodedSize(len);

	if (vbob->err != NULL)
		return (-1);
	if (size_len != 0) {
		for (size_t i = 0; i < size_len; i++)
			hdr[i + 1] = (len >> ((size_len - 1 - i) * 8)) & 0xFF;
		written += size_len;
	}
	return (VSB_bcat(vbob->vsb, hdr, written));
}

static int
VBOB_AddHeaderFloat(struct vbob *vbob, char len)
{
	char hdr;

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
		vbob->err = half_prec_float_no_support_err;
		return (-1);
	default:
		vbob->err = invalid_float_size_err;
		return (-1);
	}
	hdr = (VBOR_FLOAT_SIMPLE << 5) | len;
	return (VSB_bcat(vbob->vsb, &hdr, 1));
}

struct vbob *
VBOB_Alloc(unsigned max_depth)
{
	struct vbob *vbob;

	ALLOC_FLEX_OBJ(vbob, pos, max_depth, VBOB_MAGIC);
	vbob->vsb = VSB_new_auto();
	vbob->max_depth = max_depth;
	vbob->depth = -1;
	vbob->err = NULL;
	memset(vbob->pos, 0, sizeof(struct vbob_pos) * max_depth);
	return (vbob);
}

int
VBOB_AddUInt(struct vbob *vbob, uint64_t value)
{

	CHECK_OBJ_NOTNULL(vbob, VBOB_MAGIC);
	if (vbob->err != NULL)
		return (-1);
	if (VBOB_Update_cursor(vbob, VBOR_UINT, 0) != 0)
		return (-1);
	return (VBOB_AddHeader(vbob, VBOR_UINT, value));
}

int
VBOB_AddNegint(struct vbob *vbob, uint64_t value)
{

	CHECK_OBJ_NOTNULL(vbob, VBOB_MAGIC);
	if (vbob->err != NULL)
		return (-1);
	if (VBOB_Update_cursor(vbob, VBOR_NEGINT, 0) != 0)
		return (-1);
	return (VBOB_AddHeader(vbob, VBOR_NEGINT, value - 1));
}

int
VBOB_AddString(struct vbob *vbob, const char *value, size_t len)
{

	CHECK_OBJ_NOTNULL(vbob, VBOB_MAGIC);
	if (vbob->err != NULL)
		return (-1);
	if (VBOB_Update_cursor(vbob, VBOR_TEXT_STRING, 0))
		return (-1);
	if (VBOB_AddHeader(vbob, VBOR_TEXT_STRING, len))
		return (-1);
	return (VSB_bcat(vbob->vsb, value, len));
}

int
VBOB_AddByteString(struct vbob *vbob, const uint8_t *value, size_t len)
{

	CHECK_OBJ_NOTNULL(vbob, VBOB_MAGIC);
	if (vbob->err != NULL)
		return (-1);
	if (VBOB_Update_cursor(vbob, VBOR_BYTE_STRING, 0))
		return (-1);
	if (VBOB_AddHeader(vbob, VBOR_BYTE_STRING, len))
		return (-1);
	return (VSB_bcat(vbob->vsb, value, len));
}

int
VBOB_AddArray(struct vbob *vbob, size_t num_items)
{

	CHECK_OBJ_NOTNULL(vbob, VBOB_MAGIC);
	if (vbob->err != NULL)
		return (-1);
	if (VBOB_Update_cursor(vbob, VBOR_ARRAY, num_items))
		return (-1);
	return (VBOB_AddHeader(vbob, VBOR_ARRAY, num_items));
}

int
VBOB_AddMap(struct vbob *vbob, size_t num_pairs)
{

	CHECK_OBJ_NOTNULL(vbob, VBOB_MAGIC);
	if (vbob->err != NULL)
		return (-1);
	if (VBOB_Update_cursor(vbob, VBOR_MAP, num_pairs))
		return (-1);
	return (VBOB_AddHeader(vbob, VBOR_MAP, num_pairs));
}

int
VBOB_AddTag(struct vbob *vbob, uint64_t value)
{

	CHECK_OBJ_NOTNULL(vbob, VBOB_MAGIC);
	if (vbob->err != NULL)
		return (-1);
	if (VBOB_Update_cursor(vbob, VBOR_TAG, 0))
		return (-1);
	return (VBOB_AddHeader(vbob, VBOR_TAG, value));
}

int
VBOB_AddSimple(struct vbob *vbob, uint8_t value)
{
	uint8_t wr[2];

	CHECK_OBJ_NOTNULL(vbob, VBOB_MAGIC);
	if (vbob->err != NULL)
		return (-1);
	if (VBOB_Update_cursor(vbob, VBOR_FLOAT_SIMPLE, 0))
		return (-1);
	wr[0] = VBOR_FLOAT_SIMPLE << 5;
	if (value <= 23) {
		wr[0] |= value;
		return (VSB_bcat(vbob->vsb, wr, 1));
	}
	else if (value < 32) {
		vbob->err = invalid_simple_value_err;
		return (-1);
	}
	wr[0] |= 24;
	wr[1] = value;
	return (VSB_bcat(vbob->vsb, wr, 2));
}

int
VBOB_AddBool(struct vbob *vbob, unsigned value)
{

	return (VBOB_AddSimple(vbob, value ? 21 : 20));
}

int
VBOB_AddNull(struct vbob *vbob)
{

	return (VBOB_AddSimple(vbob, 22));
}

int
VBOB_AddUndefined(struct vbob *vbob)
{

	return (VBOB_AddSimple(vbob, 23));
}

int
VBOB_AddFloat(struct vbob *vbob, float value)
{

	CHECK_OBJ_NOTNULL(vbob, VBOB_MAGIC);
	if (vbob->err != NULL)
		return (-1);
	if (VBOB_Update_cursor(vbob, VBOR_FLOAT_SIMPLE, 0))
		return (-1);
	if (VBOB_AddHeaderFloat(vbob, 4))
		return (-1);
	invert_bytes((uint8_t *)&value, 4);
	return VSB_bcat(vbob->vsb, &value, 4);
}

int
VBOB_AddDouble(struct vbob *vbob, double value)
{

	CHECK_OBJ_NOTNULL(vbob, VBOB_MAGIC);
	if (vbob->err != NULL)
		return (-1);
	if (VBOB_Update_cursor(vbob, VBOR_FLOAT_SIMPLE, 0))
		return (-1);
	if (VBOB_AddHeaderFloat(vbob, 8))
		return (-1);
	invert_bytes((uint8_t *)&value, 8);
	return VSB_bcat(vbob->vsb, &value, 8);
}

const char *
VBOB_GetError(const struct vbob *vbob)
{

	CHECK_OBJ_NOTNULL(vbob, VBOB_MAGIC);
	return vbob->err;
}

int
VBOB_Finish(struct vbob *vbob, struct vbor *vbor)
{
	size_t data_len;
	uint8_t *data;

	CHECK_OBJ_NOTNULL(vbob, VBOB_MAGIC);
	AN(vbor);
	if (vbob->err || vbob->depth != (unsigned)-1 || VSB_finish(vbob->vsb) == -1)
		return (-1);
	data_len = VSB_len(vbob->vsb);
	if (data_len == (size_t)-1)
		return (-1);
	data = malloc(data_len);
	memcpy(data, VSB_data(vbob->vsb), data_len);
	return (VBOR_Init(vbor, data, data_len, vbob->max_depth));
}

void
VBOB_Destroy(struct vbob **vbob)
{

	AN(vbob);
	CHECK_OBJ_NOTNULL(*vbob, VBOB_MAGIC);
	VSB_destroy(&(*vbob)->vsb);
	FREE_OBJ(*vbob);
}

void
VBOC_Init(struct vboc *vboc, const struct vbor *vbor)
{
	AN(vboc);
	CHECK_OBJ_NOTNULL(vbor, VBOR_MAGIC);
	vboc->magic = VBOC_MAGIC;
	vboc->src = vbor;
	vboc->current[0].magic = 0;
}

void
VBOC_Fini(struct vboc *vboc)
{
	CHECK_OBJ_NOTNULL(vboc, VBOC_MAGIC);
	memset(vboc, 0, sizeof(*vboc));
}

enum vbor_type
VBOC_Next(struct vboc *vboc, struct vbor *vbor)
{
	CHECK_OBJ_NOTNULL(vboc, VBOC_MAGIC);
	enum vbor_type type;
	enum vbor_argument arg;
	size_t len;
	size_t skip;

	if (vboc->current->magic == 0) {
		if (VBOR_Copy(vboc->current, vboc->src))
			return (VBOR_ERROR);
		if (VBOR_Copy(vbor, vboc->current))
			return (VBOR_ERROR);
		return (VBOR_What(vboc->current));
	}
	if (vboc->current->len <= 0) {
		memcpy(vbor, vboc->current, sizeof (struct vbor));
		return (VBOR_END);
	}
	if (VBOR_GetHeader(vboc->current, &type, &arg, &len))
		return (VBOR_ERROR);
	if (VBOR_GetByteSize(vboc->current, &skip))
		return (VBOR_ERROR);
	if (vboc->current->len - skip <= 0) {
		vboc->current->len = 0;
		memcpy(vbor, vboc->current, sizeof (struct vbor));
		return (VBOR_END);
	}
	if (VBOR_Init(vboc->current, vboc->current->data + skip,
	    vboc->current->len - skip, vboc->current->max_depth) == -1)
		return (VBOR_ERROR);
	if (vbor)
		memcpy(vbor, &vboc->current[0], sizeof(*vbor));
	return (VBOR_What(vboc->current));
}

static unsigned
is_nb_float(const char *str)
{
	while (isdigit(*str))
		str++;
	return (*str == '.');
}

static const char *
get_str_end(const char *str)
{
	unsigned escaped = 0;

	while (*str != '\0') {
		if (!escaped && *str == '"')
			break;
		if (*str == '\\')
			escaped = 1;
		else
			escaped = 0;
		str++;
	}
	return (*str == '"' ? str : NULL);
}

static size_t
json_count_elements(const char *json)
{
	size_t count = 1;
	char closing;
	unsigned depth;
	char sub_opening;
	char sub_closing;

	if (*json != '{' && *json != '[')
		return (-1);
	closing = *json == '[' ? ']' : '}';
	json++;
	while (isspace(*json))
		json++;
	if (*json == closing)
		return (0);
	while (*json != '\0' && *json != closing) {
		if (*json == ',') {
			count++;
			json++;
			continue;
		}
		if (*json == '[' || *json == '{') {
			depth = 1;
			sub_opening = *json;
			sub_closing = sub_opening == '[' ? ']' : '}';
			while (*json != '\0' && depth != 0)
			{
				json++;
				if (*json == '"') {
					json = get_str_end(json);
					if (json == NULL)
						return (-1);
					continue;
				}
				else if (*json == sub_opening)
					depth++;
				else if (*json == sub_closing)
					depth--;
			}
			if (*json == '\0' || depth != 0)
				return (-1);
		}
		else if (*json == '"') {
			json++;
			json = get_str_end(json);
			if (json == NULL)
				return (-1);
		}
		json++;
	}
	return (count);
}

int
VBOB_ParseJSON(struct vbob *vbob, const char *json)
{
	int sign = 1;
	size_t count;
	char *endptr;
	const char *end;
	double dval;
	uint64_t val;

	AN(json);
	AN(vbob);
	while (*json != '\0' && !vbob->err) {
		if (isspace(*json) || *json == ',' || *json == ':' || *json == '}'
		    || *json == ']')
		{
			json++;
			continue;
		}
		switch (*json) {
		case '{':;
			count = json_count_elements(json);
			if (count == (size_t)-1) {
				vbob->err = json_closing_err;
				break;
			}
			VBOB_AddMap(vbob, count);
			json++;
			break;
		case '[':
			count = json_count_elements(json);
			if (count == (size_t)-1) {
				vbob->err = json_closing_err;
				break;
			}
			VBOB_AddArray(vbob, count);
			json++;
			break;
		case '}':
		case ']':
			json++;
			break;
		case '-':
			sign = -1;
			json++;
			if (!isdigit(*json))
				vbob->err = json_bad_number_err;
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
			endptr = NULL;
			if (is_nb_float(json)) {
				dval = strtod(json, &endptr);
				json = endptr;
				VBOB_AddDouble(vbob, dval * sign);
			}
			else {
				val = strtoul(json, &endptr, 10);
				json = endptr;
				sign == -1 ? VBOB_AddNegint(vbob, val) : VBOB_AddUInt(vbob, val);
			}
			sign = 1;
			break;
		case '"':
			json++;
			end = get_str_end(json);
			if (end == NULL) {
				vbob->err = json_unterminated_str_err;
				break;
			}
			VBOB_AddString(vbob, json, end - json);
			json += (end - json) + 1;
			break;
		case 't':
		case 'f':
		case 'n':
			if (!memcmp(json, "true", sizeof("true") - 1)) {
				VBOB_AddBool(vbob, 1);
				json += sizeof("true");
			}
			else if (!memcmp(json, "false", sizeof("false") - 1)) {
				VBOB_AddBool(vbob, 0);
				json += sizeof("false");
			}
			else if (!memcmp(json, "null", sizeof("null") - 1)) {
				VBOB_AddNull(vbob);
				json += sizeof("null");
			}
			else
				vbob->err = json_unrecognized_val_err;
			break;
		default:
			vbob->err = json_unrecognized_val_err;
		}
	}
	return (vbob->err == NULL ? 0 : -1);
}
