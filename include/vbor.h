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

#include <stdint.h>
#include <stdlib.h>

struct vsb;

enum vbor_major_type {
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
	VBOR_UNKNOWN, // XXX
	VBOR_ERROR,
};

struct vbor {
	unsigned	magic;
#define VBOR_MAGIC	0x97675fd9
	const uint8_t	*data;
	size_t		len;
	unsigned	max_depth;
	int 		flags;
#define VBOR_ALLOCATED	(1 << 0)
#define VBOR_OWNS_DATA	(1 << 1)
};

void		VBOR_Destroy(struct vbor **vbor);

int		VBOR_Init(struct vbor *vbor, const uint8_t *data, size_t len, unsigned max_depth);
int		VBOR_Copy(struct vbor *dst, const struct vbor *src);
void		VBOR_Fini(struct vbor *vbor);

int		VBOR_PrintJSON(const struct vbor *vbor, struct vsb *json, unsigned pretty);

int	VBOR_GetUInt(const struct vbor *vbor, uint64_t *res);
int	VBOR_GetNegint(const struct vbor *vbor, uint64_t *res);
int	VBOR_GetString(const struct vbor *vbor, const char **res, size_t *len);
int	VBOR_GetByteString(const struct vbor *vbor, const uint8_t **res, size_t *len);
int	VBOR_GetArraySize(const struct vbor *vbor, size_t *len);
int	VBOR_GetMapSize(const struct vbor *vbor, size_t *len);
int	VBOR_GetTag(const struct vbor *vbor, uint64_t *res);
int	VBOR_GetSimple(const struct vbor *vbor, uint8_t *res);
int	VBOR_GetBool(const struct vbor *vbor, unsigned *res);
int	VBOR_GetFloat(const struct vbor *vbor, float *res);
int	VBOR_GetDouble(const struct vbor *vbor, double *res);

int	VBOR_GetByteSize(struct vbor *vbor, size_t *len);

enum vbor_major_type	VBOR_What(const struct vbor *vbor);

int VBOR_Inside(const struct vbor *vbor, struct vbor *inside);

enum vbor_json_parse_status {
	JSON_PARSE_OK = 0,
	JSON_PARSE_UNRECOGNIZED_VAL,
	JSON_PARSE_BAD_NUMBER,
	JSON_PARSE_UNTERMINATED_STR,
	JSON_PARSE_MISSING_CLOSING_CH,
};

struct vbob_pos {
	size_t	pos;
	size_t	len;
};

struct vbob {
	unsigned	magic;
#define VBOB_MAGIC	0x3abff812
	int		err;
	struct vsb	*vsb;
	unsigned	max_depth;
	unsigned	depth;
	struct vbob_pos	pos[];
};

struct vbob	*VBOB_Alloc(unsigned max_depth);
int		VBOB_ParseJSON(struct vbob *vbob, const char *json);

int	VBOB_AddUInt(struct vbob *vbob, uint64_t value);
int	VBOB_AddNegint(struct vbob *vbob, uint64_t value);
int	VBOB_AddString(struct vbob *vbob, const char *value, size_t len);
int	VBOB_AddByteString(struct vbob *vbob, const uint8_t *value, size_t len);
int	VBOB_AddArray(struct vbob *vbob, size_t num_items);
int	VBOB_AddMap(struct vbob *vbob, size_t num_pairs);
int	VBOB_AddTag(struct vbob *vbob, uint64_t value);
int	VBOB_AddSimple(struct vbob *vbob, uint8_t value);
int	VBOB_AddBool(struct vbob *vbob, unsigned value);
int	VBOB_AddNull(struct vbob *vbob);
int	VBOB_AddUndefined(struct vbob *vbob);
int	VBOB_AddFloat(struct vbob *vbob, float value);
int	VBOB_AddDouble(struct vbob *vbob, double value);

int	VBOB_Finish(struct vbob *vbob, struct vbor *vbor);
void	VBOB_Destroy(struct vbob **vbob);

struct vboc
{
	unsigned	magic;
#define VBOC_MAGIC	0x863baac8
	struct vbor	*src;
	struct vbor	current[1];
};

int			VBOC_Init(struct vboc *vboc, struct vbor *vbor);
void 			VBOC_Fini(struct vboc *vboc);

enum vbor_major_type	VBOC_Next(struct vboc *vboc, struct vbor *vbor);

#endif
