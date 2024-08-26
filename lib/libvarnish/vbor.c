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

#include <math.h>
#include <string.h>

#include "vdef.h"

#include "miniobj.h"
#include "vas.h"
#include "vbor.h"

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
