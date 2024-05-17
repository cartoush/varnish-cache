/*-
 * Copyright (c) 2019 Varnish Software AS
 * All rights reserved.
 *
 * Author: Poul-Henning Kamp <phk@phk.freebsd.dk>
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
 *
 * VCL/VMOD symbol table
 */

#include "config.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "mgt/mgt.h"
#include "mgt/mgt_vcl.h"

#include "vbor.h"
#include "vcli_serve.h"

/*--------------------------------------------------------------------*/

static void
mgt_vcl_import_vcl(struct vclprog *vp1, struct vbor *vbor_map, size_t map_size)
{
	struct vclprog *vp2 = NULL;
	struct vboc vboc;
	struct vbor next;
	struct vbor *res = NULL;
	const char *name;
	size_t name_len = 0;

	CHECK_OBJ_NOTNULL(vp1, VCLPROG_MAGIC);
	CHECK_OBJ_NOTNULL(vbor_map, VBOR_MAGIC);

	VBOC_Init(&vboc, vbor_map);
	assert(VBOC_Next(&vboc, &next) == VBOR_MAP);
	for (size_t ctr = 0; ctr < map_size; ctr++) {
		assert(VBOC_Next(&vboc, &next) < VBOR_END);
		if (ctr % 2 == 0) {
			assert(VBOR_What(&next) == VBOR_TEXT_STRING);
			assert(VBOR_GetString(&next, &name, &name_len) == 0);
			if (name_len == sizeof("name") - 1 && !strncmp(name, "name", name_len)) {
				assert(VBOC_Next(&vboc, &next) == VBOR_TEXT_STRING);
				ctr++;
				assert(VBOR_GetString(&next, &name, &name_len) == 0);
				name = strndup(name, name_len);
				vp2 = mcf_vcl_byname(name);
				free((void*)name);
			}
		}
	}
	CHECK_OBJ_NOTNULL(vp2, VCLPROG_MAGIC);
	ALLOC_OBJ(res, VBOR_MAGIC);
	VBOR_Copy(res, vbor_map);
	mgt_vcl_dep_add(vp1, vp2)->vb = res;
}

static int
mgt_vcl_cache_vmod(const char *nm, const char *fm, const char *to)
{
	int fi, fo;
	int ret = 0;
	ssize_t sz;
	char buf[BUFSIZ];

	fo = open(to, O_WRONLY | O_CREAT | O_EXCL, 0744);
	if (fo < 0 && errno == EEXIST)
		return (0);
	if (fo < 0) {
		fprintf(stderr, "While creating copy of vmod %s:\n\t%s: %s\n",
			nm, to, VAS_errtxt(errno));
		return (1);
	}
	fi = open(fm, O_RDONLY);
	if (fi < 0) {
		fprintf(stderr, "Opening vmod %s from %s: %s\n",
			nm, fm, VAS_errtxt(errno));
		AZ(unlink(to));
		closefd(&fo);
		return (1);
	}
	while (1) {
		sz = read(fi, buf, sizeof buf);
		if (sz == 0)
			break;
		if (sz < 0 || sz != write(fo, buf, sz)) {
			fprintf(stderr, "Copying vmod %s: %s\n",
				nm, VAS_errtxt(errno));
			AZ(unlink(to));
			ret = 1;
			break;
		}
	}
	closefd(&fi);
	AZ(fchmod(fo, 0444));
	closefd(&fo);
	return (ret);
}

static void
mgt_vcl_import_vmod(struct vclprog *vp, struct vbor *vbor_map, size_t map_size)
{
	struct vmodfile *vf;
	struct vmoddep *vd;
	char *v_name = NULL;
	char *v_file = NULL;
	char *v_dst = NULL;
	unsigned res = 0;
	struct vbor next;
	struct vboc vboc;

	CHECK_OBJ_NOTNULL(vp, VCLPROG_MAGIC);
	CHECK_OBJ_NOTNULL(vbor_map, VBOR_MAGIC);
	VBOC_Init(&vboc, vbor_map);
	assert(VBOC_Next(&vboc, &next) == VBOR_MAP);
	for (size_t ctr = 0; ctr < map_size; ctr++) {
		const char *val;
		size_t val_len;

		assert(VBOC_Next(&vboc, &next) < VBOR_END);
		if (ctr % 2 == 0)
		{
			assert(VBOR_What(&next) == VBOR_TEXT_STRING);
			assert(VBOR_GetString(&next, &val, &val_len) == 0);
			if (val_len == sizeof("vext") - 1 && !strncmp(val, "vext", val_len))
			{
				assert(VBOC_Next(&vboc, &next) == VBOR_BOOL);
				ctr++;
				assert(VBOR_GetBool(&next, &res) == 0);
				if (res) {
					if (v_name)
						free(v_name);
					if (v_file)
						free(v_file);
					if (v_dst)
						free(v_dst);
					return;
				}
			}
			else if (val_len == sizeof("name") - 1 && !strncmp(val, "name", val_len))
			{
				assert(VBOC_Next(&vboc, &next) == VBOR_TEXT_STRING);
				ctr++;
				assert(VBOR_GetString(&next, &val, &val_len) == 0);
				v_name = strndup(val, val_len);
			}
			else if (val_len == sizeof("file") - 1 && !strncmp(val, "file", val_len))
			{
				assert(VBOC_Next(&vboc, &next) == VBOR_TEXT_STRING);
				ctr++;
				assert(VBOR_GetString(&next, &val, &val_len) == 0);
				v_file = strndup(val, val_len);
			}
			else if (val_len == sizeof("dst") - 1 && !strncmp(val, "dst", val_len))
			{
				assert(VBOC_Next(&vboc, &next) == VBOR_TEXT_STRING);
				ctr++;
				assert(VBOR_GetString(&next, &val, &val_len) == 0);
				v_dst = strndup(val, val_len);
			}
		}
	}
	AN(v_name);
	AN(v_file);
	AN(v_dst);
	VTAILQ_FOREACH(vf, &vmodhead, list)
	if (!strcmp(vf->fname, v_dst))
		break;
	if (vf == NULL)
	{
		ALLOC_OBJ(vf, VMODFILE_MAGIC);
		AN(vf);
		REPLACE(vf->fname, v_dst);
		VTAILQ_INIT(&vf->vcls);
		AZ(mgt_vcl_cache_vmod(v_name, v_file, v_dst));
		VTAILQ_INSERT_TAIL(&vmodhead, vf, list);
	}
	free(v_name);
	free(v_file);
	free(v_dst);
	ALLOC_OBJ(vd, VMODDEP_MAGIC);
	AN(vd);
	vd->to = vf;
	VTAILQ_INSERT_TAIL(&vp->vmods, vd, lfrom);
	VTAILQ_INSERT_TAIL(&vf->vcls, vd, lto);
}

void
mgt_vcl_symtab(struct vclprog *vp, const char *input)
{
	struct vbor vbor, next;
	struct vbob *vbob;
	struct vboc vboc;

	CHECK_OBJ_NOTNULL(vp, VCLPROG_MAGIC);
	AN(input);
	vbob = VBOB_Alloc(10);
	VBOB_ParseJSON(vbob, input);
	if (VBOB_Finish(vbob, &vbor) == -1)
		fprintf(stderr, "FATAL: Symtab parse error\n");
	VBOB_Destroy(&vbob);
	CHECK_OBJ_NOTNULL(&vbor, VBOR_MAGIC);
	ALLOC_OBJ(vp->symtab, VBOR_MAGIC);
	AN(vp->symtab);
	VBOR_Copy(vp->symtab, &vbor);
	vp->symtab->flags = VBOR_ALLOCATED | VBOR_OWNS_DATA;
	VBOC_Init(&vboc, &vbor);
	assert(VBOC_Next(&vboc, &next) == VBOR_ARRAY);
	while (VBOC_Next(&vboc, &next) < VBOR_END) {
		size_t map_size;
		struct vbor map_begin;
		const char *dir_val = NULL;
		size_t dir_val_len = 0;
		const char *type_val = NULL;AN(vp->symtab);
		size_t type_val_len = 0;

		assert(VBOR_What(&next) == VBOR_MAP);
		assert(VBOR_GetMapSize(&next, &map_size) == 0);
		memcpy(&map_begin, &next, sizeof(map_begin));
		map_size *= 2;
		for (size_t ctr = 0; ctr < map_size; ctr++) {
			assert(VBOC_Next(&vboc, &next) < VBOR_END);
			if (ctr % 2 == 0 && (dir_val == NULL || type_val == NULL)) {
				const char *val;
				size_t val_len;

				assert(VBOR_What(&next) == VBOR_TEXT_STRING);
				assert(VBOR_GetString(&next, &val, &val_len) == 0);
				if (val_len == sizeof("dir") - 1 && !strncmp("dir", val, val_len)) {
					assert(VBOC_Next(&vboc, &next) == VBOR_TEXT_STRING);
					ctr++;
					assert(VBOR_GetString(&next, &dir_val, &dir_val_len) == 0);
				}
				else if (val_len == sizeof("type") - 1 && !strncmp("type", val, val_len)) {
					assert(VBOC_Next(&vboc, &next) == VBOR_TEXT_STRING);
					ctr++;
					assert(VBOR_GetString(&next, &type_val, &type_val_len) == 0);
				}
			}
		}
		if (!dir_val || (dir_val_len != sizeof("import") - 1 || strncmp("import", dir_val, dir_val_len)))
			continue;
		AN(type_val);
		if (type_val_len == sizeof("$VMOD") - 1 && !strncmp("$VMOD", type_val, type_val_len))
			mgt_vcl_import_vmod(vp, &map_begin, map_size);
		else if (type_val_len == sizeof("$VCL") - 1 && !strncmp("$VCL", type_val, type_val_len))
			mgt_vcl_import_vcl(vp, &map_begin, map_size);
		else
			WRONG("Bad symtab import entry");
	}
}

void
mgt_vcl_symtab_clean(struct vclprog *vp)
{
	if (vp->symtab)
		VBOR_Destroy(&vp->symtab);
}

/*--------------------------------------------------------------------*/

static void
mcf_vcl_vbor_dump_map(struct cli *cli, struct vboc *vboc, int indent)
{
	struct vbor next;
	size_t len;
	const char *sval;
	size_t val_len;

	VCLI_Out(cli, "%*s{object}\n", indent, "");
	VBOR_GetMapSize(vboc->current, &len);
	len *= 2;
	for (size_t ctr = 0; ctr < len; ctr++) {
		assert(VBOC_Next(vboc, &next) < VBOR_END);
		if (ctr % 2 == 0) {
			assert(VBOR_What(&next) == VBOR_TEXT_STRING);
			assert(VBOR_GetString(&next, &sval, &val_len) == 0);
			VCLI_Out(cli, "%*s[\"%.*s\"]: ", indent + 2, "", (int)val_len, sval);
		}
		else {
			enum vbor_major_type type;
			unsigned bval;
			uint64_t uval;

			type = VBOR_What(&next);
			switch (type) {
				case VBOR_TEXT_STRING:
					assert(VBOR_GetString(&next, &sval, &val_len) == 0);
					VCLI_Out(cli, "{string} <%.*s>", (int)val_len, sval);
					break;
				case VBOR_BOOL:
					assert(VBOR_GetBool(&next, &bval) == 0);
					VCLI_Out(cli, "{%s}", bval ? "true" : "false");
					break;
				case VBOR_UINT:
					assert(VBOR_GetUInt(&next, &uval) == 0);
					VCLI_Out(cli, "{number} <%lu>", uval);
					break;
				default:
					// xxx: check if its accurate
					WRONG("Bad vbor type");
			}
			VCLI_Out(cli, "\n");
		}
	}
}

static void
mcf_vcl_vbor_dump(struct cli *cli, const struct vbor *vbor, int indent)
{
	enum vbor_major_type type;
	struct vboc vboc;
	struct vbor next;
	size_t array_size = 1;

	CHECK_OBJ_NOTNULL(cli, CLI_MAGIC);
	CHECK_OBJ_NOTNULL(vbor, VBOR_MAGIC);
	assert(VBOC_Init(&vboc, (struct vbor*)vbor) == 0);
	type = VBOR_What(vbor);
	if (type == VBOR_ARRAY) {
		VBOC_Next(&vboc, &next);
		assert(VBOR_GetArraySize(&next, &array_size) == 0);
		VCLI_Out(cli, "%*s{array}\n", indent, "");
	}
	else if (type != VBOR_MAP) {
		WRONG("Bad vbor type");
	}
	for (size_t ctr = 0; ctr < array_size; ctr++) {
		assert(VBOC_Next(&vboc, &next) == VBOR_MAP);
		mcf_vcl_vbor_dump_map(cli, &vboc, indent + 2);
	}
}

void v_matchproto_(cli_func_t)
mcf_vcl_symtab(struct cli *cli, const char * const *av, void *priv)
{
	struct vclprog *vp;
	struct vcldep *vd;

	(void)av;
	(void)priv;
	VTAILQ_FOREACH(vp, &vclhead, list) {
		if (mcf_is_label(vp))
			VCLI_Out(cli, "Label: %s\n", vp->name);
		else
			VCLI_Out(cli, "Vcl: %s\n", vp->name);
		if (!VTAILQ_EMPTY(&vp->dfrom)) {
			VCLI_Out(cli, "  imports from:\n");
			VTAILQ_FOREACH(vd, &vp->dfrom, lfrom) {
				VCLI_Out(cli, "    %s\n", vd->to->name);
				if (vd->vb)
					mcf_vcl_vbor_dump(cli, vd->vb, 6);
			}
		}
		if (!VTAILQ_EMPTY(&vp->dto)) {
			VCLI_Out(cli, "  exports to:\n");
			VTAILQ_FOREACH(vd, &vp->dto, lto) {
				VCLI_Out(cli, "    %s\n", vd->from->name);
				if (vd->vb)
					mcf_vcl_vbor_dump(cli, vd->vb, 6);
			}
		}
		if (vp->symtab != NULL) {
			VCLI_Out(cli, "  symtab:\n");
			mcf_vcl_vbor_dump(cli, vp->symtab, 4);
		}
	}
}
