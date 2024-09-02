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
 * Turn vmod JSON spec into symbols
 *
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>

#include "vcc_compile.h"

#include "libvcc.h"
#include "vbor.h"

#include "vcc_vmod.h"
#include "vsb.h"

struct vmod_obj {
	unsigned		magic;
#define VMOD_OBJ_MAGIC		0x349885f8
	char			*name;
	struct type		type[1];
	VTAILQ_ENTRY(vmod_obj)	list;
};

static void
vcc_VmodObject(struct vcc *tl, struct symbol *sym)
{
	struct vmod_obj *obj;
	struct vsb *buf;

	buf = VSB_new_auto();
	AN(buf);

	VSB_printf(buf, "%s.%s", sym->vmod_name, sym->name);
	AZ(VSB_finish(buf));

	ALLOC_OBJ(obj, VMOD_OBJ_MAGIC);
	AN(obj);
	REPLACE(obj->name, VSB_data(buf));

	INIT_OBJ(obj->type, TYPE_MAGIC);
	obj->type->name = obj->name;
	sym->type = obj->type;
	VTAILQ_INSERT_TAIL(&tl->vmod_objects, obj, list);
	VSB_destroy(&buf);
}

static void
alias_sym(struct vcc *tl, const struct symbol *psym, const struct vbor *v)
{
	char *alias = NULL, *func = NULL;
	struct symbol *sym;
	struct vsb *buf;
	struct vboc vboc;
	struct vbor next;
	const char *val = NULL;
	size_t val_len = 0;

	buf = VSB_new_auto();
	AN(buf);

	VCC_SymName(buf, psym);

	VBOC_Init(&vboc, v);
	assert(VBOC_Next(&vboc, &next) == VBOR_TEXT_STRING);
	assert(!VBOR_GetString(&next, &val, &val_len));

	VSB_printf(buf, ".%.*s", (int)val_len, val);
	AZ(VSB_finish(buf));
	REPLACE(alias, VSB_data(buf));

	assert(VBOC_Next(&vboc, &next) == VBOR_TEXT_STRING);
	assert(!VBOR_GetString(&next, &val, &val_len));

	VBOC_Fini(&vboc);
	VBOR_Fini(&next);

	VSB_clear(buf);
	VCC_SymName(buf, psym);
	VSB_printf(buf, ".%.*s", (int)val_len, val);
	AZ(VSB_finish(buf));
	REPLACE(func, VSB_data(buf));

	sym = VCC_MkSymAlias(tl, alias, func);
	AN(sym);
	assert(sym->kind == SYM_FUNC || sym->kind == SYM_METHOD);
	VSB_destroy(&buf);
	free(alias);
	free(func);
}

static void
func_restrict(struct vcc *tl, struct symbol *sym, vcc_kind_t kind, const struct vbor *v)
{
	struct vboc vboc;
	struct vbor next;
	const char *val = NULL;
	size_t val_len = 0;

	CHECK_OBJ_NOTNULL(v, VBOR_MAGIC);
	AN(sym);

	if (kind != SYM_FUNC && kind != SYM_METHOD)
		return;

	assert(!VBOR_Inside(v, &next));
	VBOC_Init(&vboc, &next);

	assert(VBOC_Next(&vboc, &next) == VBOR_TEXT_STRING);
	assert(!VBOR_GetString(&next, &val, &val_len));

	if (val_len != sizeof("$RESTRICT") - 1 || strncmp(val, "$RESTRICT", val_len))
		return;

	assert(VBOC_Next(&vboc, &next) == VBOR_ARRAY);
	assert(!VBOR_Inside(&next, &next));
	sym->r_methods = 0;
	VBOR_FOREACH(&vboc, &next, &next) {
		unsigned s = 0;

		assert(VBOR_What(&next) == VBOR_TEXT_STRING);
		assert(!VBOR_GetString(&next, &val, &val_len));
#define VCL_CTX(l,H) \
		if (VBOR_STRING_LITERAL_MATCH(#l, val, val_len)) s = VCL_MET_##H;
#include "tbl/vcl_context.h"
		if (!s) {
			VSB_printf(tl->sb, "Error in vmod \"%s\", invalid scope for $Restrict: %.*s\n",sym->vmod_name, (int)val_len, val);
			tl->err = 1;
			break;
		}
		sym->r_methods |= s;
	}
	VBOC_Fini(&vboc);
	VBOR_Fini(&next);
}

static void
func_sym(struct vcc *tl, vcc_kind_t kind, const struct symbol *psym,
    const struct vbor *v, const struct vbor *vv)
{
	struct vbor *vbor;
	struct symbol *sym;
	struct vsb *buf;
	struct vboc vboc;
	struct vbor next;
	const char *val = NULL;
	size_t val_len = 0;
	char *type = NULL;

	CHECK_OBJ_NOTNULL(vv, VBOR_MAGIC);

	if (kind == SYM_ALIAS) {
		alias_sym(tl, psym, v);
		return;
	}

	buf = VSB_new_auto();
	AN(buf);

	VBOC_Init(&vboc, v);
	assert(VBOC_Next(&vboc, &next) == VBOR_TEXT_STRING);
	assert(!VBOR_GetString(&next, &val, &val_len));

	VCC_SymName(buf, psym);
	VSB_printf(buf, ".%.*s", (int)val_len, val);
	AZ(VSB_finish(buf));
	sym = VCC_MkSym(tl, VSB_data(buf), SYM_MAIN, kind, VCL_LOW, VCL_HIGH);
	AN(sym);
	VSB_destroy(&buf);

	ALLOC_OBJ(vbor, VBOR_MAGIC); // XXX: Find a way not to allocate this
	VBOR_Copy(vbor, v);

	if (kind == SYM_OBJECT) {
		VBOR_Copy(vbor, &next);
		sym->eval_priv = vbor;
		sym->vmod_name = psym->vmod_name;
		sym->r_methods = VCL_MET_INIT;
		vcc_VmodObject(tl, sym);
		vcc_VmodSymbols(tl, sym);
		VBOC_Fini(&vboc);
		VBOR_Fini(&next);
		return;
	}

	if (kind == SYM_METHOD)
		sym->extra = psym->rname;

	assert(VBOC_Next(&vboc, &next) == VBOR_ARRAY);
	sym->action = vcc_Act_Call;
	sym->vmod_name = psym->vmod_name;
	sym->eval = vcc_Eval_SymFunc;
	VBOR_Copy(vbor, &next);
	sym->eval_priv = vbor;

	assert(!VBOR_Inside(&next, &next));
	assert(VBOR_What(&next) == VBOR_ARRAY);
	assert(!VBOR_Inside(&next, &next));
	assert(VBOR_What(&next) == VBOR_TEXT_STRING);
	assert(!VBOR_GetString(&next, &val, &val_len));
	type = strndup(val, val_len);
	sym->type = VCC_Type(type);
	free(type);
	AN(sym->type);
	sym->r_methods = VCL_MET_TASK_ALL;
	func_restrict(tl, sym, kind, vv);
	VBOC_Fini(&vboc);
	VBOR_Fini(&next);
}

void
vcc_VmodSymbols(struct vcc *tl, const struct symbol *sym)
{
	const struct vbor *vbor;
	struct vboc vboc;
	struct vboc vboc2;
	struct vboc vboc3;
	struct vbor next;
	vcc_kind_t kind;
	enum vbor_type type;
	const char *val;
	size_t val_len;

	CAST_OBJ_NOTNULL(vbor, sym->eval_priv, VBOR_MAGIC);
	if (sym->kind == SYM_VMOD) {
		assert(VBOR_What(vbor) == VBOR_ARRAY);
		assert(!VBOR_Inside(vbor, &next));
		VBOC_Init(&vboc, &next);
	} else if (sym->kind != SYM_OBJECT)
		WRONG("symbol kind");
	else
		VBOC_Init(&vboc, vbor);

	while ((type = VBOC_Next(&vboc, &next)) < VBOR_END) {
		val = NULL;
		val_len = 0;
		if (type != VBOR_ARRAY) {
			continue;
		}

		assert(!VBOR_Inside(&next, &next));
		VBOC_Init(&vboc2, &next);
		assert(VBOC_Next(&vboc2, &next) == VBOR_TEXT_STRING);
		assert(!VBOR_GetString(&next, &val, &val_len));
		if ((type = VBOC_Next(&vboc2, &next)) != VBOR_TEXT_STRING)
			continue;
		kind = SYM_NONE;
#define STANZA(UU, ll, ss) \
	if (VBOR_STRING_LITERAL_MATCH("$" #UU, val, val_len)) kind = ss;
		STANZA_TBL
#undef STANZA
		if (kind != SYM_NONE) {
			VBOC_Init(&vboc3, vboc.current);
			assert(VBOC_Next(&vboc3, &next) == VBOR_ARRAY);
			VBOC_Next(&vboc3, &next);
			func_sym(tl, kind, sym, vboc2.current, &next);
			VBOC_Fini(&vboc3);
			ERRCHK(tl);
		}
		VBOC_Fini(&vboc2);
	}
	VBOC_Fini(&vboc);
	VBOR_Fini(&next);
}

void v_matchproto_(sym_act_f)
vcc_Act_New(struct vcc *tl, struct token *t, struct symbol *sym)
{
	struct symbol *isym, *osym;
	struct inifin *ifp;
	struct vsb *buf;
	const struct vbor *vbor;
	struct vbor vbor2;
	struct vboc vboc;
	struct vboc vboc2;
	struct vbor next;
	const char *val = NULL;
	size_t val_len = 0;
	unsigned null_ok = -1;
	size_t arr_len = 0;

	(void)sym;
	(void)t;

	ExpectErr(tl, ID);
	vcc_ExpectVid(tl, "VCL object");
	ERRCHK(tl);
	isym = VCC_HandleSymbol(tl, INSTANCE);
	ERRCHK(tl);
	AN(isym);
	isym->noref = 1;
	isym->action = vcc_Act_Obj;

	SkipToken(tl, '=');
	ExpectErr(tl, ID);
	osym = VCC_SymbolGet(tl, SYM_MAIN, SYM_OBJECT, SYMTAB_EXISTING,
	    XREF_NONE);
	ERRCHK(tl);
	AN(osym);

	/* Scratch the generic INSTANCE type */
	isym->type = osym->type;

	CAST_OBJ_NOTNULL(vbor, osym->eval_priv, VBOR_MAGIC);
	// vbor = object name

	isym->vmod_name = osym->vmod_name;
	isym->eval_priv = vbor;

	VBOC_Init(&vboc, vbor);
	assert(VBOC_Next(&vboc, &next) == VBOR_TEXT_STRING);
	assert(VBOC_Next(&vboc, &next) == VBOR_MAP);
	assert(!VBOR_Inside(&next, &next));
	// vbor = flags

	VBOR_FOREACH(&vboc2, &next, &next) {
		assert(VBOR_What(&next) == VBOR_TEXT_STRING);
		assert(!VBOR_GetString(&next, &val, &val_len));
		assert(VBOC_Next(&vboc2, &next) < VBOR_END);
		if (VBOR_STRING_LITERAL_MATCH("NULL_OK", val, val_len)) {
			assert(!VBOR_GetBool(&next, &null_ok));
			break;
		}
	}
	if (!null_ok)
		VTAILQ_INSERT_TAIL(&tl->sym_objects, isym, sideways);

	assert(VBOC_Next(&vboc, &next) == VBOR_TEXT_STRING);
	// vbor = struct name
	assert(!VBOR_GetString(&next, &val, &val_len));
	Fh(tl, 0, "static %.*s *%s;\n\n", (int)val_len, val, isym->rname);

	assert(VBOC_Next(&vboc, &next) == VBOR_ARRAY);
	assert(!VBOR_GetArraySize(&next, &arr_len));
	assert(!VBOR_Inside(&next, &next));
	VBOC_Init(&vboc2, &next);
	assert(VBOC_Next(&vboc2, &next) == VBOR_TEXT_STRING);
	assert(!VBOR_GetString(&next , &val, &val_len));
	assert(VBOR_STRING_LITERAL_MATCH("$INIT", val, val_len));

	assert(VBOC_Next(&vboc2, &vbor2) == VBOR_ARRAY);
	assert(VBOC_Next(&vboc, &next) == VBOR_ARRAY);
	buf = VSB_new_auto();
	AN(buf);
	VSB_printf(buf, "&%s, \"%s\"", isym->rname, isym->name);
	AZ(VSB_finish(buf));
	vcc_Eval_Func(tl, &vbor2, VSB_data(buf), osym);
	VSB_destroy(&buf);
	ERRCHK(tl);
	SkipToken(tl, ';');
	isym->def_e = tl->t;

	assert(!VBOR_Inside(&next, &next));
	VBOC_Init(&vboc, &next);
	assert(VBOC_Next(&vboc, &next) == VBOR_TEXT_STRING);
	assert(!VBOR_GetString(&next, &val, &val_len));
	assert(VBOR_STRING_LITERAL_MATCH("$FINI", val, val_len));

	assert(VBOC_Next(&vboc, &next) == VBOR_ARRAY);
	assert(!VBOR_Inside(&next, &next));
	VBOC_Init(&vboc, &next);
	assert(VBOC_Next(&vboc, &next) == VBOR_ARRAY);
	assert(!VBOR_Inside(&next, &next));
	assert(VBOR_What(&next) == VBOR_TEXT_STRING);
	assert(VBOC_Next(&vboc, &next) == VBOR_TEXT_STRING);
	assert(!VBOR_GetString(&next, &val, &val_len));
	ifp = New_IniFin(tl);
	VSB_printf(ifp->fin, "\t\tif (%s)\n", isym->rname);
	VSB_printf(ifp->fin, "\t\t\t\t%.*s(&%s);", (int)val_len, val, isym->rname);
}
