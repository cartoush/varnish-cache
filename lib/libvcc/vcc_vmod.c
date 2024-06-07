/*-
 * Copyright (c) 2010-2015 Varnish Software AS
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
 * Parse `import`, check metadata and versioning.
 *
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>

#include "vcc_compile.h"

#include "libvcc.h"
#include "vfil.h"
#include "vbor.h"
#include "vmod_abi.h"

#include "vcc_vmod.h"
#include "vsb.h"

struct vmod_import {
	unsigned			magic;
#define VMOD_IMPORT_MAGIC		0x31803a5d
	const char			*err;
	struct vsb			*json;
	char				*path;
	VTAILQ_ENTRY(vmod_import)	list;
	int				from_vext;
	int				unimported_vext;

	// From $VMOD
	double				vmod_syntax;
	char				*name;
	char				*func_name;
	char				*file_id;
	char				*abi;
	unsigned			major;
	unsigned			minor;

	struct symbol			*sym;
	const struct token		*t_mod;
	struct vbor			*vb;
#define STANZA(UU, ll, ss)		int n_##ll;
	STANZA_TBL
#undef STANZA
};

static VTAILQ_HEAD(,vmod_import) imports = VTAILQ_HEAD_INITIALIZER(imports);

typedef void vcc_do_stanza_f(struct vcc *tl, const struct vmod_import *vim,
    const struct vbor *vb);

static int
vcc_Extract_JSON(struct vmod_import *vim, const char *filename)
{
	const char *magic = "VMOD_JSON_SPEC\x02", *p;
	int c;
	FILE *f;

	CHECK_OBJ_NOTNULL(vim, VMOD_IMPORT_MAGIC);
	AN(filename);

	f = fopen(filename, "rb");
	if (f == NULL) {
		vim->err = strerror(errno);
		return (-1);
	}

	p = magic;
	vim->err = "No VMOD JSON found";
	while (1) {
		c = getc(f);
		if (c == EOF) {
			AZ(fclose(f));
			vim->err = "No VMOD JSON found";
			return (-1);
		}
		if (c != *p) {
			p = magic;
			continue;
		}
		p++;
		if (*p == '\0')
			break;
	}

	vim->json = VSB_new_auto();
	AN(vim->json);

	while (1) {
		c = getc(f);
		if (c == EOF) {
			AZ(fclose(f));
			vim->err = "Truncated VMOD JSON";
			VSB_destroy(&vim->json);
			return (-1);
		}
		if (c == '\x03')
			break;
		VSB_putc(vim->json, c);
	}
	AZ(fclose(f));
	AZ(VSB_finish(vim->json));
	return (0);
}

static const char *jsn_parse_str[] = {
	NULL,
	"Unrecognized value",
	"Bad number",
	"Unterminated string",
	"Closing character missing"
};

static const char *
vcc_ParseJSON(const struct vcc *tl, const char *jsn, struct vmod_import *vim)
{
	struct vbob *vbob = NULL;
	struct vboc vboc;
	struct vbor next;
	const char *val = NULL;
	size_t val_len = 0;
	char *p;
	enum vbor_json_parse_status json_parse_res = JSON_PARSE_OK;

	vbob = VBOB_Alloc(10);
	AN(vbob);
	json_parse_res = VBOB_ParseJSON(vbob, jsn);
	fprintf(stderr, "json_parse_res : %d\n", json_parse_res);
	ALLOC_OBJ(vim->vb, VBOR_MAGIC);
	if (VBOB_Finish(vbob, vim->vb) == -1) {
		if (json_parse_res > JSON_PARSE_OK)
			return jsn_parse_str[json_parse_res];
		return NULL;
	}
	vim->vb->flags = VBOR_ALLOCATED | VBOR_OWNS_DATA;

	VBOC_Init(&vboc, vim->vb);
	if (VBOC_Next(&vboc, &next) != VBOR_ARRAY)
		return "Not array[0]";
	if (VBOC_Next(&vboc, &next) != VBOR_ARRAY)
		return "Not array[1]";
	if (VBOC_Next(&vboc, &next) != VBOR_TEXT_STRING)
		return "Not string[2]";
	assert(!VBOR_GetString(&next, &val, &val_len));
	fprintf(stderr, "vmod ? : %.*s\n", (int)val_len, val);
	if (val_len != sizeof("$VMOD") - 1 || strncmp(val, "$VMOD", val_len) != 0)
		return "Not $VMOD[3]";

	assert(VBOC_Next(&vboc, &next) == VBOR_TEXT_STRING);
	assert(!VBOR_GetString(&next, &val, &val_len));
	val = strndup(val, val_len);
	AN(val);
	vim->vmod_syntax = strtod(val, NULL);
	free((void*)val);
	assert(vim->vmod_syntax == 1.0);

	assert(VBOC_Next(&vboc, &next) == VBOR_TEXT_STRING);
	assert(!VBOR_GetString(&next, &val, &val_len));
	vim->name = strndup(val, val_len);
	assert(VBOC_Next(&vboc, &next) == VBOR_TEXT_STRING);
	assert(!VBOR_GetString(&next, &val, &val_len));
	vim->func_name = strndup(val, val_len);
	assert(VBOC_Next(&vboc, &next) == VBOR_TEXT_STRING);
	assert(!VBOR_GetString(&next, &val, &val_len));
	vim->file_id = strndup(val, val_len);
	assert(VBOC_Next(&vboc, &next) == VBOR_TEXT_STRING);
	assert(!VBOR_GetString(&next, &val, &val_len));
	vim->abi = strndup(val, val_len);

	assert(VBOC_Next(&vboc, &next) == VBOR_TEXT_STRING);
	assert(!VBOR_GetString(&next, &val, &val_len));
	val = strndup(val, val_len);
	AN(val);
	vim->major = strtoul(val, &p, 10);
	assert(p == NULL || *p == '\0' || *p == 'U');
	free((void*)val);

	assert(VBOC_Next(&vboc, &next) == VBOR_TEXT_STRING);
	assert(!VBOR_GetString(&next, &val, &val_len));
	val = strndup(val, val_len);
	AN(val);
	vim->minor = strtoul(val, &p, 10);
	assert(p == NULL || *p == '\0' || *p == 'U');
	free((void*)val);

	if (vim->major == 0 && vim->minor == 0 &&
		strcmp(vim->abi, VMOD_ABI_Version)) {
		VSB_printf(tl->sb, "Incompatible VMOD %.*s\n", PF(vim->t_mod));
		VSB_printf(tl->sb, "\tFile name: %s\n", vim->path);
		VSB_printf(tl->sb, "\tABI mismatch, expected <%s>, got <%s>\n",
			VMOD_ABI_Version, vim->abi);
		return ("");
	}
	if (vim->major != 0 &&
		(vim->major != VRT_MAJOR_VERSION ||
		vim->minor > VRT_MINOR_VERSION)) {
		VSB_printf(tl->sb, "Incompatible VMOD %.*s\n", PF(vim->t_mod));
		VSB_printf(tl->sb, "\tFile name: %s\n", vim->path);
		VSB_printf(tl->sb, "\tVMOD wants ABI version %u.%u\n",
			vim->major, vim->minor);
		VSB_printf(tl->sb, "\tvarnishd provides ABI version %u.%u\n",
			VRT_MAJOR_VERSION, VRT_MINOR_VERSION);
		return ("");
	}

	assert(!VBOC_Init(&vboc, vim->vb));
	assert(VBOC_Next(&vboc, &next) == VBOR_ARRAY);
	size_t top_size = 0;
	assert(!VBOR_GetArraySize(&next, &top_size));
	for (size_t i = 0; i < top_size; i++) {
		size_t sub_size = 0;
		assert(VBOC_Next(&vboc, &next) == VBOR_ARRAY);
		assert(!VBOR_GetArraySize(&next, &sub_size));
		assert(VBOC_Next(&vboc, &next) == VBOR_TEXT_STRING);
		assert(!VBOR_GetString(&next, &val, &val_len));
		assert(val[0] == '$');

		unsigned valid_stanza = 0;
#define STANZA(UU, ll, ss) \
		if (!strncmp(val, "$" #UU, val_len)) {vim->n_##ll++; valid_stanza = 1;}
			STANZA_TBL
#undef STANZA
		if (!valid_stanza)
			return ("Unknown metadata stanza.");
		for (size_t j = 1; j < sub_size; j++) {
			size_t s = 0;
			assert(VBOC_Next(&vboc, &next) < VBOR_END);
			if (VBOR_What(&next) == VBOR_ARRAY) {
				assert(!VBOR_GetArraySize(&next, &s));
				sub_size += s;
			}
			else if (VBOR_What(&next) == VBOR_MAP) {
				assert(!VBOR_GetMapSize(&next, &s));
				sub_size += s * 2;
			}
		}
	}

	if (vim->n_cproto != 1)
		return ("Bad cproto stanza(s)");
	if (vim->n_vmod != 1)
		return ("Bad vmod stanza(s)");
	return NULL;
}

/*
 * Load and check the metadata from the objectfile containing the vmod
 */

static int
vcc_VmodLoad(struct vcc *tl, struct vmod_import *vim)
{
	static const char *err;
	struct vmod_import *vim2;

	CHECK_OBJ_NOTNULL(vim, VMOD_IMPORT_MAGIC);

	err = vcc_ParseJSON(tl, VSB_data(vim->json), vim);
	if (err != NULL && *err != '\0') {
		VSB_printf(tl->sb,
		    "VMOD %.*s: bad metadata\n", PF(vim->t_mod));
		VSB_printf(tl->sb, "\t(%s)\n", err);
		VSB_printf(tl->sb, "\tFile name: %s\n", vim->path);
	}

	if (err != NULL)
		return (-1);

	VTAILQ_FOREACH(vim2, &imports, list) {
		if (strcmp(vim->name, vim2->name))
			continue;
		if (!strcmp(vim->file_id, vim2->file_id)) {
			// (Truly) duplicate imports are OK
			return (0);
		}
		VSB_printf(tl->sb,
			"Different version of VMOD %.*s already loaded\n",
			PF(vim->t_mod));
		vcc_ErrWhere(tl, vim->t_mod);
		VSB_cat(tl->sb, "Previous import at:\n");
		vcc_ErrWhere(tl, vim2->t_mod);
		vcc_Warn(tl);
		break;
	}
	VTAILQ_INSERT_TAIL(&imports, vim, list);

	return (0);
}

static void v_matchproto_(vcc_do_stanza_f)
vcc_do_event(struct vcc *tl, const struct vmod_import *vim,
	const struct vbor *vb)
{
	struct inifin *ifp;
	const char *val = NULL;
	size_t val_len = 0;

	assert(VBOR_What(vb) == VBOR_TEXT_STRING);
	assert(!VBOR_GetString(vb, &val, &val_len));

	ifp = New_IniFin(tl);
	VSB_printf(ifp->ini,
		"\tif (%.*s(ctx, &vmod_priv_%s, VCL_EVENT_LOAD))\n"
		"\t\treturn(1);",
		(int)val_len, val, vim->sym->vmod_name);
	VSB_printf(ifp->fin,
		"\t\t(void)%.*s(ctx, &vmod_priv_%s,\n"
		"\t\t\t    VCL_EVENT_DISCARD);",
		(int)val_len, val, vim->sym->vmod_name);
	VSB_printf(ifp->event, "%.*s(ctx, &vmod_priv_%s, ev)",
		(int)val_len, val, vim->sym->vmod_name);
}

static void v_matchproto_(vcc_do_stanza_f)
vcc_do_cproto(struct vcc *tl, const struct vmod_import *vim,
	const struct vbor *vb)
{
	struct vbor next;
	struct vboc vboc;

	const char *val = NULL;
	size_t val_len = 0;

	(void)vim;
	VBOC_Init(&vboc, (struct vbor*)vb);
	assert(VBOR_What(vb) == VBOR_TEXT_STRING);
	assert(!VBOR_GetString(vb, &val, &val_len));

	char *cproto = NULL;
	size_t proto_len = 0;
	while (VBOC_Next(&vboc, &next) == VBOR_TEXT_STRING) {
		const char *val = NULL;
		size_t val_len = 0;

		assert(!VBOR_GetString(&next, &val, &val_len));
		if (proto_len < val_len) {
			// fprintf(stderr, "mallocing %ld bytes\n", val_len);
			cproto = malloc(val_len + 1);
			proto_len = val_len;
		}
		char *p = cproto;
 		for (size_t i = 0; i < val_len; i++, p++) {
			if (val[i] == '\\') {
				if (val[i + 1] == 't') {
					*p = '\t';
					i++;
				}
			}
			else
				*p = val[i];
		}
		*p = '\0';
		// fprintf(stderr, "DOING CPROTO : %s\n", cproto);
		Fh(tl, 0, "%s\n", cproto);
	}
	free(cproto);
}

static void
vcc_vb_foreach(struct vcc *tl, const struct vmod_import *vim,
	const char *stanza, vcc_do_stanza_f *func)
{
	struct vbor next;
	struct vboc vboc;
	size_t top_size;
	const char *val = NULL;
	size_t val_len = 0;

	VBOC_Init(&vboc, (struct vbor*)vim->vb);
	assert(VBOC_Next(&vboc, &next) == VBOR_ARRAY);
	assert(!VBOR_GetArraySize(&next, &top_size));
	for (size_t i = 0; i < top_size; i++) {
		size_t sub_size = 0;

		int a = VBOC_Next(&vboc, &next);
		assert(a == VBOR_ARRAY);
		assert(!VBOR_GetArraySize(&next, &sub_size));
		assert(VBOC_Next(&vboc, &next) == VBOR_TEXT_STRING);
		assert(!VBOR_GetString(&next, &val, &val_len));
		// assert(VBOC_Next(&vboc, &next) < VBOR_END);
		if (val_len == strlen(stanza) && strncmp(val, stanza, val_len) == 0) {
			assert(VBOC_Next(&vboc, &next) == VBOR_TEXT_STRING);
			sub_size--;
			func(tl, vim, &next);
		}
		for (size_t j = 1; j < sub_size; j++) {
			assert(VBOC_Next(&vboc, &next) < VBOR_END);
			size_t s = 0;
			if (VBOR_What(&next) == VBOR_ARRAY) {
				assert(!VBOR_GetArraySize(&next, &s));
				sub_size += s;
			}
			else if (VBOR_What(&next) == VBOR_MAP) {
				assert(!VBOR_GetMapSize(&next, &s));
				sub_size += 2 * s;
			}
			// assert(VBOC_Next(&vboc, &next) < VBOR_END);
		}
	}
}

static void
vcc_emit_setup(struct vcc *tl, const struct vmod_import *vim)
{
	struct inifin *ifp;
	const struct token *mod = vim->t_mod;

	ifp = New_IniFin(tl);
	VSB_cat(ifp->ini, "\tif (VPI_Vmod_Init(ctx,\n");
	VSB_printf(ifp->ini, "\t    &VGC_vmod_%.*s,\n", PF(mod));
	VSB_printf(ifp->ini, "\t    %u,\n", tl->vmod_count++);
	VSB_printf(ifp->ini, "\t    &%s,\n", vim->func_name);
	VSB_printf(ifp->ini, "\t    sizeof(%s),\n", vim->func_name);
	VSB_printf(ifp->ini, "\t    \"%.*s\",\n", PF(mod));
	VSB_cat(ifp->ini, "\t    ");
	VSB_quote(ifp->ini, vim->path, -1, VSB_QUOTE_CSTR);
	VSB_cat(ifp->ini, ",\n");
	AN(vim->file_id);
	VSB_printf(ifp->ini, "\t    \"%s\",\n", vim->file_id);
	if (vim->from_vext) {
		VSB_cat(ifp->ini, "\t    ");
		VSB_quote(ifp->ini, vim->path, -1, VSB_QUOTE_CSTR);
		VSB_cat(ifp->ini, "\n");
	} else {
		VSB_printf(ifp->ini, "\t    \"./vmod_cache/_vmod_%.*s.%s\"\n",
			PF(mod), vim->file_id);
	}
	VSB_cat(ifp->ini, "\t    ))\n");
	VSB_cat(ifp->ini, "\t\treturn(1);");

	VSB_cat(tl->symtab, ",\n    {\n");
	VSB_cat(tl->symtab, "\t\"dir\": \"import\",\n");
	VSB_cat(tl->symtab, "\t\"type\": \"$VMOD\",\n");
	VSB_printf(tl->symtab, "\t\"name\": \"%.*s\",\n", PF(mod));
	if (vim->from_vext)
		VSB_cat(tl->symtab, "\t\"vext\": true,\n");
	else
		VSB_cat(tl->symtab, "\t\"vext\": false,\n");
	VSB_printf(tl->symtab, "\t\"file\": \"%s\",\n", vim->path);
	VSB_printf(tl->symtab, "\t\"dst\": \"./vmod_cache/_vmod_%.*s.%s\"\n",
		PF(mod), vim->file_id);
	VSB_cat(tl->symtab, "    }");

	/* XXX: zero the function pointer structure ?*/
	VSB_printf(ifp->fin, "\t\tVRT_priv_fini(ctx, &vmod_priv_%.*s);",
		PF(mod));
	VSB_printf(ifp->final, "\t\tVPI_Vmod_Unload(ctx, &VGC_vmod_%.*s);",
		PF(mod));

	// fprintf(stderr, "%s %s %d\n", __FILE__, __FUNCTION__, __LINE__);
	vcc_vb_foreach(tl, vim, "$EVENT", vcc_do_event);

	Fh(tl, 0, "\n/* --- BEGIN VMOD %.*s --- */\n\n", PF(mod));
	Fh(tl, 0, "static struct vmod *VGC_vmod_%.*s;\n", PF(mod));
	Fh(tl, 0, "static struct vmod_priv vmod_priv_%.*s;\n", PF(mod));

	vcc_vb_foreach(tl, vim, "$CPROTO", vcc_do_cproto);

	Fh(tl, 0, "\n/* --- END VMOD %.*s --- */\n\n", PF(mod));
}

static void
vcc_vim_destroy(struct vmod_import **vimp)
{
	struct vmod_import *vim;

	TAKE_OBJ_NOTNULL(vim, vimp, VMOD_IMPORT_MAGIC);
	if (vim->path)
		free(vim->path);
	if (vim->vb) {
		struct vbor *v = vim->vb;
		if (v->flags & VBOR_ALLOCATED)
			VBOR_Destroy(&v);
		else
			VBOR_Fini(vim->vb);
	}
	if (vim->json)
		VSB_destroy(&vim->json);
	FREE_OBJ(vim);
}

static int
vcc_path_open(void *priv, const char *fn)
{
	struct vmod_import *vim;

	CAST_OBJ_NOTNULL(vim, priv, VMOD_IMPORT_MAGIC);
	AN(fn);

	return (vcc_Extract_JSON(vim, fn));
}

void
vcc_ParseImport(struct vcc *tl)
{
	char fn[1024];
	const char *p;
	struct token *mod, *tmod, *t1;
	struct symbol *msym, *vsym;
	struct vmod_import *vim = NULL;
	const struct vmod_import *vimold;

	t1 = tl->t;
	SkipToken(tl, ID);		/* "import" */

	ExpectErr(tl, ID);		/* "vmod_name" */
	mod = tl->t;
	tmod = vcc_PeekTokenFrom(tl, mod);
	AN(tmod);
	if (tmod->tok == ID && vcc_IdIs(tmod, "as")) {
		vcc_NextToken(tl);		/* "vmod_name" */
		vcc_NextToken(tl);		/* "as" */
		ExpectErr(tl, ID);		/* "vcl_name" */
	}
	tmod = tl->t;

	msym = VCC_SymbolGet(tl, SYM_MAIN, SYM_VMOD, SYMTAB_CREATE, XREF_NONE);
	ERRCHK(tl);
	AN(msym);

	bprintf(fn, "libvmod_%.*s.so", PF(mod));
	if (tl->t->tok == ID) {
		if (!vcc_IdIs(tl->t, "from")) {
			VSB_cat(tl->sb, "Expected 'from path ...'\n");
			vcc_ErrWhere(tl, tl->t);
			return;
		}
		vcc_NextToken(tl);
		if (!tl->unsafe_path && strchr(tl->t->dec, '/')) {
			VSB_cat(tl->sb,
			    "'import ... from path ...' is unsafe.\nAt:");
			vcc_ErrToken(tl, tl->t);
			vcc_ErrWhere(tl, tl->t);
			return;
		}
		ExpectErr(tl, CSTR);
		p = strrchr(tl->t->dec, '/');
		if (p != NULL && p[1] == '\0')
			bprintf(fn, "%slibvmod_%.*s.so", tl->t->dec, PF(mod));
		else
			bprintf(fn, "%s", tl->t->dec);
		vcc_NextToken(tl);
	} else {
		VTAILQ_FOREACH(vim, &imports, list) {
			if (!vcc_IdIs(mod, vim->name))
				continue;
			if (!vim->unimported_vext)
				continue;
			fprintf(stderr, "IMPORT %s from VEXT\n", vim->name);
			vim->unimported_vext = 0;
			vim->t_mod = mod;
			vim->sym = msym;
			break;
		}
	}

	SkipToken(tl, ';');

	if (vim == NULL) {
		ALLOC_OBJ(vim, VMOD_IMPORT_MAGIC);
		AN(vim);
		vim->t_mod = mod;
		vim->sym = msym;

		if (VFIL_searchpath(tl->vmod_path, vcc_path_open, vim, fn, &vim->path)) {
			if (vim->err == NULL) {
				VSB_printf(tl->sb,
				    "Could not find VMOD %.*s\n", PF(mod));
			} else {
				VSB_printf(tl->sb,
				    "Could not open VMOD %.*s\n", PF(mod));
				VSB_printf(tl->sb, "\tFile name: %s\n",
				    vim->path != NULL ? vim->path : fn);
				VSB_printf(tl->sb, "\tError: %s\n", vim->err);
			}
			vcc_ErrWhere(tl, mod);
			vcc_vim_destroy(&vim);
			return;
		}

		if (vcc_VmodLoad(tl, vim) < 0 || tl->err) {
			vcc_ErrWhere(tl, vim->t_mod);
			vcc_vim_destroy(&vim);
			return;
		}
	}

	if (!vcc_IdIs(vim->t_mod, vim->name)) {
		vcc_ErrWhere(tl, vim->t_mod);
		VSB_printf(tl->sb, "Wrong file for VMOD %.*s\n",
		    PF(vim->t_mod));
		VSB_printf(tl->sb, "\tFile name: %s\n", vim->path);
		VSB_printf(tl->sb, "\tContains vmod \"%s\"\n", vim->name);
		vcc_vim_destroy(&vim);
		return;
	}

	vimold = msym->import;
	if (vimold != NULL) {
		CHECK_OBJ(vimold, VMOD_IMPORT_MAGIC);
		if (!strcmp(vimold->file_id, vim->file_id)) {
			/* Identical import is OK */
		} else {
			VSB_printf(tl->sb,
			    "Another module already imported as %.*s.\n",
			    PF(tmod));
			vcc_ErrWhere2(tl, t1, tl->t);
		}
		vcc_vim_destroy(&vim);
		return;
	}
	msym->def_b = t1;
	msym->def_e = tl->t;

	VTAILQ_FOREACH(vsym, &tl->sym_vmods, sideways) {
		assert(vsym->kind == SYM_VMOD);
		vimold = vsym->import;
		CHECK_OBJ_NOTNULL(vimold, VMOD_IMPORT_MAGIC);
		if (!strcmp(vimold->file_id, vim->file_id)) {
			/* Already loaded under different name */
			msym->eval_priv = vsym->eval_priv;
			msym->import = vsym->import;
			msym->vmod_name = vsym->vmod_name;
			vcc_VmodSymbols(tl, msym, -1);
			AZ(tl->err);
			// XXX: insert msym in sideways ?
			vcc_vim_destroy(&vim);
			return;
		}
	}

	VTAILQ_INSERT_TAIL(&tl->sym_vmods, msym, sideways);

	msym->eval_priv = vim->vb;
	msym->import = vim;
	msym->vmod_name = TlDup(tl, vim->name);
	vcc_VmodSymbols(tl, msym, -1);
	ERRCHK(tl);

	vcc_emit_setup(tl, vim);
}

void
vcc_ImportVext(struct vcc *tl, const char *filename)
{
	struct vmod_import *vim;

	ALLOC_OBJ(vim, VMOD_IMPORT_MAGIC);
	AN(vim);

	if (vcc_Extract_JSON(vim, filename)) {
		FREE_OBJ(vim);
		return;
	}
	fprintf(stderr, "FOUND VMOD in VEXT %s\n", filename);
	if (vcc_VmodLoad(tl, vim) < 0 || tl->err) {
		// vcc_ErrWhere(tl, vim->t_mod);
		vcc_vim_destroy(&vim);
		return;
	}
	vim->from_vext = 1;
	vim->unimported_vext = 1;
	vim->path = strdup(filename);
	vim->path += 1;
	AN(vim->path);
	fprintf(stderr, "GOOD VMOD %s in VEXT %s\n", vim->name, filename);
}
