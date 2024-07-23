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

#include "vbor.h"

#include "mgt/mgt.h"
#include "mgt/mgt_vcl.h"

#include "vcli_serve.h"

/*--------------------------------------------------------------------*/

static void
mgt_vcl_import_vcl(struct vclprog *vp1, struct vbor *vbor_map)
{
	struct vclprog *vp2 = NULL;
	struct vboc vboc;
	struct vbor next;
	const char *name;
	size_t name_len = 0;
	char *aname = NULL;

	CHECK_OBJ_NOTNULL(vp1, VCLPROG_MAGIC);
	CHECK_OBJ_NOTNULL(vbor_map, VBOR_MAGIC);

	assert(VBOR_What(vbor_map) == VBOR_MAP);
	assert(!VBOR_Inside(vbor_map, &next));
	VBOC_Init(&vboc, &next);
	while (VBOC_Next(&vboc, &next) < VBOR_END) {
		assert(!VBOR_GetString(&next, &name, &name_len));
		assert(VBOC_Next(&vboc, &next) < VBOR_END);
		if (name_len == sizeof("name") - 1 && !strncmp(name, "name", name_len)) {
			assert(!VBOR_GetString(&next, &name, &name_len));
			aname = strndup(name, name_len);
			vp2 = mcf_vcl_byname(aname);
			free(aname);
		}
	}
	CHECK_OBJ_NOTNULL(vp2, VCLPROG_MAGIC);
	VBOR_Copy(mgt_vcl_dep_add(vp1, vp2)->vb, vbor_map);
	VBOC_Fini(&vboc);
	VBOR_Fini(&next);
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
mgt_vcl_import_vmod(struct vclprog *vp, struct vbor *vbor_map)
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

	assert(VBOR_What(vbor_map) == VBOR_MAP);
	assert(!VBOR_Inside(vbor_map, &next));
	VBOC_Init(&vboc, &next);
	while (VBOC_Next(&vboc, &next) < VBOR_END) {
		const char *val;
		size_t val_len;

		assert(VBOR_What(&next) == VBOR_TEXT_STRING);
		assert(!VBOR_GetString(&next, &val, &val_len));
		assert(VBOC_Next(&vboc, &next) < VBOR_END);
		if (val_len == sizeof("vext") - 1 && !strncmp(val, "vext", val_len))
		{
			assert(!VBOR_GetBool(&next, &res));
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
			assert(!VBOR_GetString(&next, &val, &val_len));
			v_name = strndup(val, val_len);
		}
		else if (val_len == sizeof("file") - 1 && !strncmp(val, "file", val_len))
		{
			assert(!VBOR_GetString(&next, &val, &val_len));
			v_file = strndup(val, val_len);
		}
		else if (val_len == sizeof("dst") - 1 && !strncmp(val, "dst", val_len))
		{
			assert(!VBOR_GetString(&next, &val, &val_len));
			v_dst = strndup(val, val_len);
		}
	}
	VBOC_Fini(&vboc);
	VBOR_Fini(&next);

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
	struct vboc vboc2;

	CHECK_OBJ_NOTNULL(vp, VCLPROG_MAGIC);
	AN(input);
	vbob = VBOB_Alloc(10);
	VBOB_ParseJSON(vbob, input);
	if (VBOB_Finish(vbob, &vbor) == -1)
		WRONG("FATAL: Symtab parse error\n");
	VBOB_Destroy(&vbob);
	CHECK_OBJ_NOTNULL(&vbor, VBOR_MAGIC);
	VBOR_Copy(vp->symtab, &vbor);
	assert(VBOR_What(&vbor) == VBOR_ARRAY);
	assert(!VBOR_Inside(&vbor, &next));
	VBOC_Init(&vboc, &next);
	while (VBOC_Next(&vboc, &next) < VBOR_END) {
		const char *dir_val = NULL;
		size_t dir_val_len = 0;
		const char *type_val = NULL;
		size_t type_val_len = 0;

		assert(VBOR_What(&next) == VBOR_MAP);
		assert(!VBOR_Inside(&next, &next));
		VBOC_Init(&vboc2, &next);
		while (VBOC_Next(&vboc2, &next) < VBOR_END) {
			const char *val;
			size_t val_len;

			assert(VBOR_What(&next) == VBOR_TEXT_STRING);
			assert(VBOR_GetString(&next, &val, &val_len) == 0);
			assert(VBOC_Next(&vboc2, &next) < VBOR_END);
			if (val_len == sizeof("dir") - 1 && !strncmp("dir", val, val_len))
				assert(VBOR_GetString(&next, &dir_val, &dir_val_len) == 0);
			else if (val_len == sizeof("type") - 1 && !strncmp("type", val, val_len))
				assert(VBOR_GetString(&next, &type_val, &type_val_len) == 0);
			if (dir_val != NULL && type_val != NULL)
				break;
		}
		if (!dir_val || (dir_val_len != sizeof("import") - 1 || strncmp("import", dir_val, dir_val_len)))
			continue;
		AN(type_val);
		if (type_val_len == sizeof("$VMOD") - 1 && !strncmp("$VMOD", type_val, type_val_len))
			mgt_vcl_import_vmod(vp, vboc.current);
		else if (type_val_len == sizeof("$VCL") - 1 && !strncmp("$VCL", type_val, type_val_len))
			mgt_vcl_import_vcl(vp, vboc.current);
		else
			WRONG("Bad symtab import entry");
	}
	VBOC_Fini(&vboc);
	VBOR_Fini(&next);
}

void
mgt_vcl_symtab_clean(struct vclprog *vp)
{
	if (vp->symtab->magic == VBOR_MAGIC)
		VBOR_Fini(vp->symtab);
}

/*--------------------------------------------------------------------*/

static void
mcf_vcl_vbor_dump_map(struct cli *cli, struct vbor *vbor, int indent)
{
	struct vboc vboc;
	struct vbor next;
	const char *sval;
	size_t val_len;
	enum vbor_type type;
	unsigned bval;
	uint64_t uval;

	VCLI_Out(cli, "%*s{object}\n", indent, "");
	assert(VBOR_What(vbor) == VBOR_MAP);
	assert(!VBOR_Inside(vbor, &next));
	VBOC_Init(&vboc, &next);
	while (VBOC_Next(&vboc, &next) < VBOR_END) {
		assert(!VBOR_GetString(&next, &sval, &val_len));
		VCLI_Out(cli, "%*s[\"%.*s\"]: ", indent + 2, "", (int)val_len, sval);

		type = VBOC_Next(&vboc, &next);
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
				WRONG("Bad vbor type");
		}
		VCLI_Out(cli, "\n");
	}
}

static void
mcf_vcl_vbor_dump(struct cli *cli, const struct vbor *vbor, int indent)
{
	enum vbor_type type;
	struct vboc vboc;
	struct vbor next;

	CHECK_OBJ_NOTNULL(cli, CLI_MAGIC);
	CHECK_OBJ_NOTNULL(vbor, VBOR_MAGIC);
	type = VBOR_What(vbor);
	if (type == VBOR_ARRAY) {
		assert(!VBOR_Inside(vbor, &next));
		VCLI_Out(cli, "%*s{array}\n", indent, "");
	}
	else if (type == VBOR_MAP)
		assert(!VBOR_Copy(&next, vbor));
	else
		WRONG("Bad vbor type");
	VBOC_Init(&vboc, &next);
	while (VBOC_Next(&vboc, &next) < VBOR_END) {
		assert(VBOR_What(&next) == VBOR_MAP);
		mcf_vcl_vbor_dump_map(cli, &next, indent + 2);
	}
	VBOC_Fini(&vboc);
	VBOR_Fini(&next);
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
				if (vd->vb->magic == VBOR_MAGIC)
					mcf_vcl_vbor_dump(cli, vd->vb, 6);
			}
		}
		if (!VTAILQ_EMPTY(&vp->dto)) {
			VCLI_Out(cli, "  exports to:\n");
			VTAILQ_FOREACH(vd, &vp->dto, lto) {
				VCLI_Out(cli, "    %s\n", vd->from->name);
				if (vd->vb->magic == VBOR_MAGIC)
					mcf_vcl_vbor_dump(cli, vd->vb, 6);
			}
		}
		if (vp->symtab->magic == VBOR_MAGIC) {
			VCLI_Out(cli, "  symtab:\n");
			mcf_vcl_vbor_dump(cli, vp->symtab, 4);
		}
	}
}
