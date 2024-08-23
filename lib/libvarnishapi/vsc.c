/*-
 * Copyright (c) 2006 Verdens Gang AS
 * Copyright (c) 2006-2015 Varnish Software AS
 * All rights reserved.
 *
 * Author: Poul-Henning Kamp <phk@phk.freebsd.dk>
 * Author: Martin Blix Grydeland <martin@varnish-software.com>
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

#include <sys/stat.h>

#include <fnmatch.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "vdef.h"
#include "vas.h"
#include "miniobj.h"
#include "vqueue.h"
#include "vbor.h"
#include "vsb.h"
#include "vsc_priv.h"

#include "vapi/vsc.h"
#include "vapi/vsm.h"

struct vsc_sf_mode {
	const char		*name;
	unsigned		include;
	unsigned		fail;
	unsigned		append;
};

static const struct vsc_sf_mode VSC_SF_INCLUDE[1] = {{"include", 1, 1, 1}};
static const struct vsc_sf_mode VSC_SF_EXCLUDE[1] = {{"exclude", 0, 0, 1}};
static const struct vsc_sf_mode VSC_SF_REQUIRE[1] = {{"require", 1, 0, 0}};

struct vsc_sf {
	unsigned			magic;
#define VSC_SF_MAGIC			0x558478dd
	VTAILQ_ENTRY(vsc_sf)		list;
	char				*pattern;
	const struct vsc_sf_mode	*mode;
};

VTAILQ_HEAD(vsc_sf_head, vsc_sf);

struct vsc_pt {
	struct VSC_point	point;
	char			*name;
};

enum vsc_seg_type {
	VSC_SEG_COUNTERS = 1,
	VSC_SEG_DOCS,
};

struct vsc_seg {
	unsigned		magic;
#define VSC_SEG_MAGIC		0x801177d4
	enum vsc_seg_type	type;
	VTAILQ_ENTRY(vsc_seg)	list;
	VTAILQ_ENTRY(vsc_seg)	doc_list;
	struct vsm_fantom	fantom[1];
	const struct vsc_head	*head;
	const char		*body;

	struct vbor		*vb;

	unsigned		npoints;
	struct vsc_pt		*points;

	int			mapped;
	int			exposed;
};
VTAILQ_HEAD(vsc_seg_head, vsc_seg);

struct vsc {
	unsigned		magic;
#define VSC_MAGIC		0x3373554a

	unsigned		raw;
	struct vsc_sf_head	sf_list;
	struct vsc_seg_head	segs;
	struct vsc_seg_head	docs;

	VSC_new_f		*fnew;
	VSC_destroy_f		*fdestroy;
	void			*priv;
};

/*--------------------------------------------------------------------
 * Build the static level, type and point descriptions
 */

enum vsc_levels {
#define VSC_LEVEL_F(v,l,e,d) v,
#include "tbl/vsc_levels.h"
};

static const struct VSC_level_desc levels[] = {
#define VSC_LEVEL_F(v,l,e,d) [v] = {#v, l, e, d},
#include "tbl/vsc_levels.h"
};

static const ssize_t nlevels = sizeof(levels)/sizeof(*levels);

/*--------------------------------------------------------------------*/

struct vsc *
VSC_New(void)
{
	struct vsc *vsc;

	ALLOC_OBJ(vsc, VSC_MAGIC);
	if (vsc == NULL)
		return (vsc);
	VTAILQ_INIT(&vsc->sf_list);
	VTAILQ_INIT(&vsc->segs);
	VTAILQ_INIT(&vsc->docs);
	return (vsc);
}

/*--------------------------------------------------------------------*/

static int
vsc_sf_arg(struct vsc *vsc, const char *glob, const struct vsc_sf_mode *mode)
{
	struct vsc_sf *sf;

	CHECK_OBJ_NOTNULL(vsc, VSC_MAGIC);
	AN(glob);
	AN(mode);

	ALLOC_OBJ(sf, VSC_SF_MAGIC);
	AN(sf);
	REPLACE(sf->pattern, glob);
	sf->mode = mode;
	AN(mode->name);
	if (mode->append)
		VTAILQ_INSERT_TAIL(&vsc->sf_list, sf, list);
	else
		VTAILQ_INSERT_HEAD(&vsc->sf_list, sf, list);
	return (1);
}

static int
vsc_f_arg(struct vsc *vsc, const char *opt)
{

	CHECK_OBJ_NOTNULL(vsc, VSC_MAGIC);
	AN(opt);

	if (opt[0] == '^')
		return (vsc_sf_arg(vsc, opt + 1, VSC_SF_EXCLUDE));
	return (vsc_sf_arg(vsc, opt, VSC_SF_INCLUDE));
}

/*--------------------------------------------------------------------*/

int
VSC_Arg(struct vsc *vsc, char arg, const char *opt)
{

	CHECK_OBJ_NOTNULL(vsc, VSC_MAGIC);

	switch (arg) {
	case 'I': return (vsc_sf_arg(vsc, opt, VSC_SF_INCLUDE));
	case 'X': return (vsc_sf_arg(vsc, opt, VSC_SF_EXCLUDE));
	case 'R': return (vsc_sf_arg(vsc, opt, VSC_SF_REQUIRE));
	case 'f': return (vsc_f_arg(vsc, opt));
	case 'r': vsc->raw = !vsc->raw; return (1);
	default: return (0);
	}
}

unsigned
VSC_IsRaw(const struct vsc *vsc)
{

	CHECK_OBJ_NOTNULL(vsc, VSC_MAGIC);
	return (vsc->raw);
}

/*--------------------------------------------------------------------
 */

static int
vsc_filter(const struct vsc *vsc, const char *nm)
{
	struct vsc_sf *sf;
	unsigned res = 0;

	CHECK_OBJ_NOTNULL(vsc, VSC_MAGIC);
	VTAILQ_FOREACH(sf, &vsc->sf_list, list) {
		if (!fnmatch(sf->pattern, nm, 0))
			return (!sf->mode->include);
		res |= sf->mode->fail;
	}
	return (res);
}

/*--------------------------------------------------------------------
 */

static void
vsc_clean_point(struct vsc_pt *point)
{
	REPLACE(point->name, NULL);
}

static void
vsc_fill_point(const struct vsc *vsc, const struct vsc_seg *seg,
    struct vbor *vbor, struct vsb *vsb, struct vsc_pt *point)
{
	struct vboc vboc;
	struct vbor next;

	const char *name = NULL;
	size_t name_len = 0;
	const char *ctype = NULL;
	size_t ctype_len = 0;
	const char *oneliner = NULL;
	size_t oneliner_len = 0;
	const char *docs = NULL;
	size_t docs_len = 0;
	const char *type = NULL;
	size_t type_len = 0;
	const char *format = NULL;
	size_t format_len = 0;
	const char *level = NULL;
	size_t level_len = 0;
	uint64_t index = -1;

	const char *kval = NULL;
	size_t kval_len = 0;
	const char *vval = NULL;
	size_t vval_len = 0;
	uint64_t uval = -1;

	CHECK_OBJ_NOTNULL(vsc, VSC_MAGIC);
	CHECK_OBJ_NOTNULL(vbor, VBOR_MAGIC);
	memset(point, 0, sizeof *point);

	assert(VBOR_What(vbor) == VBOR_MAP);
	assert(!VBOR_Inside(vbor, &next));
	assert(!VBOC_Init(&vboc, &next));
	while (VBOC_Next(&vboc, &next) < VBOR_END) {
		assert(!VBOR_GetString(&next, &kval, &kval_len));
		switch (VBOC_Next(&vboc, &next)) {
			case VBOR_TEXT_STRING:
				assert(!VBOR_GetString(&next, &vval, &vval_len));
				break;
			case VBOR_UINT:
				assert(!VBOR_GetUInt(&next, &uval));
				break;
			default:
				WRONG("Invalid JSON type here");
		}
		if (sizeof("name") - 1 == kval_len && !strncmp(kval, "name", kval_len)) {
			name = vval;
			name_len = vval_len;
		}
		else if (sizeof("ctype") - 1 == kval_len && !strncmp(kval, "ctype", kval_len)) {
			ctype = vval;
			ctype_len = vval_len;
		}
		else if (sizeof("oneliner") - 1 == kval_len && !strncmp(kval, "oneliner", kval_len)) {
			oneliner = vval;
			oneliner_len = vval_len;
		}
		else if (sizeof("docs") - 1 == kval_len && !strncmp(kval, "docs", kval_len)) {
			docs = vval;
			docs_len = vval_len;
		}
		else if (sizeof("type") - 1 == kval_len && !strncmp(kval, "type", kval_len)) {
			type = vval;
			type_len = vval_len;
		}
		else if (sizeof("format") - 1 == kval_len && !strncmp(kval, "format", kval_len)) {
			format = vval;
			format_len = vval_len;
		}
		else if (sizeof("level") - 1 == kval_len && !strncmp(kval, "level", kval_len)) {
			level = vval;
			level_len = vval_len;
		}
		else if (sizeof("index") - 1 == kval_len && !strncmp(kval, "index", kval_len)) {
			index = uval;
		}
	}
	VBOR_Fini(&next);

	AN(name);
	AN(ctype);
	AN(oneliner);
	AN(docs);
	AN(type);
	AN(format);
	AN(level);
	assert(index != -1);

	VSB_clear(vsb);
	VSB_printf(vsb, "%s.%.*s", seg->fantom->ident, (int)name_len, name);
	AZ(VSB_finish(vsb));

	if (vsc_filter(vsc, VSB_data(vsb)))
		return;

	point->name = strdup(VSB_data(vsb));
	AN(point->name);
	point->point.name = point->name;

	point->point.ctype = strndup(ctype, ctype_len);
	point->point.sdesc = strndup(oneliner,  oneliner_len);
	point->point.ldesc = strndup(docs, docs_len);

	if (sizeof("counter") - 1 == type_len && !strncmp(type, "counter", type_len))
		point->point.semantics = 'c';
	else if (sizeof("gauge") - 1 == type_len && !strncmp(type, "gauge", type_len))
		point->point.semantics = 'g';
	else if (sizeof("bitmap") - 1 == type_len && !strncmp(type, "bitmap", type_len))
		point->point.semantics = 'b';
	else
		point->point.semantics = '?';

	if (sizeof("integer") - 1 == format_len && !strncmp("integer", format, format_len))
		point->point.format = 'i';
	else if (sizeof("bytes") - 1 == format_len && !strncmp("bytes", format, format_len))
		point->point.format = 'B';
	else if (sizeof("bitmap") - 1 == format_len && !strncmp("bitmap", format, format_len))
		point->point.format = 'b';
	else if (sizeof("duration") - 1 == format_len && !strncmp("duration", format, format_len))
		point->point.format = 'd';
	else
		point->point.format = '?';

	if (sizeof("info") - 1 == level_len && !strncmp(level, "info", level_len))
		point->point.level = &levels[info];
	else if (sizeof("diag") - 1 == level_len && !strncmp(level, "diag", level_len))
		point->point.level = &levels[diag];
	else if (sizeof("debug") - 1 == level_len && !strncmp(level, "debug", level_len))
		point->point.level = &levels[debug];
	else
		WRONG("Illegal level");

	point->point.ptr = (volatile void*)(seg->body + index);
	point->point.raw = vsc->raw;
}

static void
vsc_del_seg(const struct vsc *vsc, struct vsm *vsm, struct vsc_seg **spp)
{
	unsigned u;
	struct vsc_pt *pp;
	struct vsc_seg *sp;

	CHECK_OBJ_NOTNULL(vsc, VSC_MAGIC);
	AN(vsm);
	TAKE_OBJ_NOTNULL(sp, spp, VSC_SEG_MAGIC);
	AZ(VSM_Unmap(vsm, sp->fantom));
	if (sp->vb != NULL)
		VBOR_Destroy(&sp->vb);
	else {
		pp = sp->points;
		for (u = 0; u < sp->npoints; u++, pp++)
			vsc_clean_point(pp);
		free(sp->points);
	}
	FREE_OBJ(sp);
}

static struct vsc_seg *
vsc_new_seg(const struct vsm_fantom *fp, enum vsc_seg_type type)
{
	struct vsc_seg *sp;

	ALLOC_OBJ(sp, VSC_SEG_MAGIC);
	AN(sp);
	*sp->fantom = *fp;
	sp->type = type;

	return (sp);
}

static void
vsc_unmap_seg(const struct vsc *vsc, struct vsm *vsm, struct vsc_seg *sp)
{
	unsigned u;
	struct vsc_pt *pp;

	CHECK_OBJ_NOTNULL(vsc, VSC_MAGIC);
	AN(vsm);
	CHECK_OBJ_NOTNULL(sp, VSC_SEG_MAGIC);

	AZ(sp->exposed);
	if (!sp->mapped)
		return;

	if (sp->type == VSC_SEG_COUNTERS) {
		pp = sp->points;
		for (u = 0; u < sp->npoints; u++, pp++)
			vsc_clean_point(pp);
		free(sp->points);
		sp->points = NULL;
		sp->npoints = 0;
		AZ(sp->vb);
	} else if (sp->type == VSC_SEG_DOCS) {
		if (sp->vb != NULL)
			VBOR_Destroy(&sp->vb);
		AZ(sp->vb);
		AZ(sp->points);
	} else {
		WRONG("Invalid segment type");
	}

	AZ(VSM_Unmap(vsm, sp->fantom));
	sp->head = NULL;
	sp->body = NULL;
	sp->mapped = 0;
}

static int
vsc_map_seg(const struct vsc *vsc, struct vsm *vsm, struct vsc_seg *sp)
{
	struct vboc vboc;
	struct vbor next, elem;
	const struct vsc_head *head;
	struct vsc_seg *spd;
	struct vsb *vsb;
	struct vsc_pt *pp;
	int retry;
	const char *val = NULL;
	size_t map_len = 0;
	size_t val_len = 0;
	size_t elements_nb = 0;

	CHECK_OBJ_NOTNULL(vsc, VSC_MAGIC);
	AN(vsm);
	CHECK_OBJ_NOTNULL(sp, VSC_SEG_MAGIC);

	if (sp->mapped)
		return (0);

	AZ(sp->exposed);

	if (VSM_Map(vsm, sp->fantom))
		return (-1);
	head = sp->fantom->b;

	/* It isn't ready yet. Sleep and try again. If it still
	 * isn't ready, fail the mapping. The transitions inside
	 * varnishd that we are waiting for are just some memcpy()
	 * operations, so there is no reason to allow a long retry
	 * time. */
	for (retry = 10; retry > 0 && head->ready == 0; retry--)
		usleep(10000);

	if (head->ready == 0) {
		AZ(VSM_Unmap(vsm, sp->fantom));
		return (-1);
	}

	sp->head = head;
	sp->body = (char*)sp->fantom->b + sp->head->body_offset;
	sp->mapped = 1;

	if (sp->type == VSC_SEG_DOCS) {
		/* Parse the DOCS json */
		struct vbob *vbob = VBOB_Alloc(10);
		AN(vbob);
		assert(!VBOB_ParseJSON(vbob, sp->body));
		ALLOC_OBJ(sp->vb, VBOR_MAGIC);
		assert(!VBOB_Finish(vbob, sp->vb));
		sp->vb->flags |= VBOR_ALLOCATED;
		VBOB_Destroy(&vbob);
		return (0);
	}

	assert(sp->type == VSC_SEG_COUNTERS);

	/* Find the corresponding DOCS seg. We are not able to
	 * read and match on the doc_id until the DOCS section is
	 * mapped. Iterate over all the DOCS sections, attempt to
	 * map if needed, and then check the doc_id. */
	VTAILQ_FOREACH(spd, &vsc->docs, doc_list) {
		CHECK_OBJ_NOTNULL(spd, VSC_SEG_MAGIC);
		assert(spd->type == VSC_SEG_DOCS);
		if (!spd->mapped && vsc_map_seg(vsc, vsm, spd))
			continue; /* Failed to map it */
		AN(spd->mapped);
		if (spd->head->doc_id == sp->head->doc_id)
			break; /* We have a match */
	}
	if (spd == NULL) {
		/* Could not find the right DOCS seg. Leave this
		 * seg as unmapped. */
		vsc_unmap_seg(vsc, vsm, sp);
		return (-1);
	}

	assert(VBOR_What(spd->vb) == VBOR_MAP);
	assert(!VBOR_Inside(spd->vb, &next));
	assert(!VBOC_Init(&vboc, &next));
	while (VBOC_Next(&vboc, &next) < VBOR_END) {
		assert(!VBOR_GetString(&next, &val, &val_len));
		assert(VBOC_Next(&vboc, &next) < VBOR_END);
		if (sizeof("elements") - 1 == val_len && !strncmp(val, "elements", val_len)) {
			assert(VBOR_What(&next) == VBOR_UINT);
			assert(!VBOR_GetUInt(&next, &elements_nb));
			sp->npoints = elements_nb;
		}
		else if (sizeof("elem") - 1 == val_len && !strncmp(val, "elem", val_len)) {
			assert(VBOR_What(&next) == VBOR_MAP);
			VBOR_Copy(&elem, &next);
		}
	}

	/* Create the VSC points list */
	assert(elements_nb != -1);
	CHECK_OBJ_NOTNULL(&elem, VBOR_MAGIC);

	sp->points = calloc(sp->npoints, sizeof *sp->points);
	AN(sp->points);
	vsb = VSB_new_auto();
	AN(vsb);

	pp = sp->points;

	elements_nb = sp->npoints;
	VBOC_Init(&vboc, &elem);
	assert(VBOC_Next(&vboc, &next) == VBOR_MAP);
	for (size_t i = 0; i < elements_nb; i++) {
		assert(VBOC_Next(&vboc, &next) == VBOR_TEXT_STRING);
		assert(VBOC_Next(&vboc, &next) == VBOR_MAP);
		vsc_fill_point(vsc, sp, &next, vsb, pp);
		pp++;
	}
	VSB_destroy(&vsb);
	VBOC_Fini(&vboc);
	VBOR_Fini(&next);
	return (0);
}

/*--------------------------------------------------------------------
 */

static void
vsc_expose(const struct vsc *vsc, struct vsc_seg *sp, int del)
{
	struct vsc_pt *pp;
	unsigned u;
	int expose;

	if (!sp->mapped) {
		AZ(sp->exposed);
		return;
	}

	if (vsc->fnew != NULL && !sp->exposed &&
	    !del && sp->head->ready == 1)
		expose = 1;
	else if (vsc->fdestroy != NULL && sp->exposed &&
	    (del || sp->head->ready == 2))
		expose = 0;
	else
		return;

	pp = sp->points;
	for (u = 0; u < sp->npoints; u++, pp++) {
		if (pp->name == NULL)
			continue;
		if (expose)
			pp->point.priv = vsc->fnew(vsc->priv, &pp->point);
		else
			vsc->fdestroy(vsc->priv, &pp->point);
	}
	sp->exposed = expose;
}

/*--------------------------------------------------------------------
 */

static void
vsc_del_segs(struct vsc *vsc, struct vsm *vsm, struct vsc_seg_head *head)
{
	struct vsc_seg *sp, *sp2;

	VTAILQ_FOREACH_SAFE(sp, head, list, sp2) {
		CHECK_OBJ(sp, VSC_SEG_MAGIC);
		VTAILQ_REMOVE(head, sp, list);
		if (sp->type == VSC_SEG_DOCS)
			VTAILQ_REMOVE(&vsc->docs, sp, doc_list);
		vsc_expose(vsc, sp, 1);
		vsc_unmap_seg(vsc, vsm, sp);
		FREE_OBJ(sp);
	}
}

/*--------------------------------------------------------------------
 */

static int
vsc_iter_seg(const struct vsc *vsc, const struct vsc_seg *sp,
    VSC_iter_f *fiter, void *priv)
{
	unsigned u;
	int i = 0;
	struct vsc_pt *pp;

	CHECK_OBJ_NOTNULL(vsc, VSC_MAGIC);
	CHECK_OBJ_NOTNULL(sp, VSC_SEG_MAGIC);
	AN(fiter);
	pp = sp->points;
	for (u = 0; u < sp->npoints && i == 0; u++, pp++) {
		if (pp->name != NULL)
			i = fiter(priv, &pp->point);
	}
	return (i);
}

int
VSC_Iter(struct vsc *vsc, struct vsm *vsm, VSC_iter_f *fiter, void *priv)
{
	enum vsc_seg_type type;
	struct vsm_fantom ifantom;
	struct vsc_seg *sp, *sp2;
	struct vsc_seg_head removed;
	int i = 0;

	CHECK_OBJ_NOTNULL(vsc, VSC_MAGIC);
	AN(vsm);

	/* First walk the VSM segment list and consolidate with the shadow
	 * VSC seg list. We avoid calling any of the callback functions
	 * while iterating the VSMs. This removes any headaches wrt to
	 * callbacks calling VSM_Status(). */
	VTAILQ_INIT(&removed);
	sp = VTAILQ_FIRST(&vsc->segs);
	VSM_FOREACH(&ifantom, vsm) {
		AN(ifantom.category);
		if (!strcmp(ifantom.category, VSC_CLASS))
			type = VSC_SEG_COUNTERS;
		else if (!strcmp(ifantom.category, VSC_DOC_CLASS))
			type = VSC_SEG_DOCS;
		else {
			/* Not one of the categories we care about */
			continue;
		}

		while (sp != NULL) {
			CHECK_OBJ_NOTNULL(sp, VSC_SEG_MAGIC);
			if (VSM_StillValid(vsm, sp->fantom) == VSM_valid &&
			    !strcmp(ifantom.ident, sp->fantom->ident)) {
				/* sp matches the expected value */
				break;
			}

			/* sp is no longer in the VSM list. Remove it from
			 * our list. */
			sp2 = sp;
			sp = VTAILQ_NEXT(sp, list);
			VTAILQ_REMOVE(&vsc->segs, sp2, list);
			VTAILQ_INSERT_TAIL(&removed, sp2, list);
		}

		if (sp == NULL) {
			/* New entries are always appended last in the VSM
			 * list. Since we have iterated past all the
			 * entries in our shadow list, the VSM entry is a
			 * new entry we have not seen before. */
			sp = vsc_new_seg(&ifantom, type);
			AN(sp);
			VTAILQ_INSERT_TAIL(&vsc->segs, sp, list);
			if (type == VSC_SEG_DOCS)
				VTAILQ_INSERT_TAIL(&vsc->docs, sp, doc_list);
		}

		assert(sp->type == type);
		sp = VTAILQ_NEXT(sp, list);
	}
	while (sp != NULL) {
		/* Clean up the tail end of the shadow list. */
		CHECK_OBJ_NOTNULL(sp, VSC_SEG_MAGIC);
		sp2 = sp;
		sp = VTAILQ_NEXT(sp, list);

		VTAILQ_REMOVE(&vsc->segs, sp2, list);
		VTAILQ_INSERT_TAIL(&removed, sp2, list);
	}

	vsc_del_segs(vsc, vsm, &removed);

	/* Iterate our shadow list, reporting on each pointer value */
	VTAILQ_FOREACH(sp, &vsc->segs, list) {
		CHECK_OBJ_NOTNULL(sp, VSC_SEG_MAGIC);

		if (sp->type != VSC_SEG_COUNTERS)
			continue;

		/* Attempt to map the VSM. This is a noop if it was
		 * already mapped. If we fail we skip this seg on this
		 * call to VSC_Iter(), but will attempt again the next
		 * time VSC_Iter() is called. */
		if (vsc_map_seg(vsc, vsm, sp))
			continue;

		/* Expose the counters if necessary */
		vsc_expose(vsc, sp, 0);

		if (fiter != NULL && sp->head->ready == 1)
			i = vsc_iter_seg(vsc, sp, fiter, priv);
		if (i)
			break;
	}

	return (i);
}

/*--------------------------------------------------------------------
 */

void
VSC_State(struct vsc *vsc, VSC_new_f *fn, VSC_destroy_f *fd, void *priv)
{
	struct vsc_seg *sp;

	CHECK_OBJ_NOTNULL(vsc, VSC_MAGIC);
	assert((fn == NULL && fd == NULL) || (fn != NULL && fd != NULL));
	if (fd == NULL) {
		VTAILQ_FOREACH(sp, &vsc->segs, list)
			vsc_expose(vsc, sp, 1);
	}
	vsc->fnew = fn;
	vsc->fdestroy = fd;
	vsc->priv = priv;
}

/*--------------------------------------------------------------------
 */

const struct VSC_level_desc *
VSC_ChangeLevel(const struct VSC_level_desc *old, int chg)
{
	int i;

	if (old == NULL)
		old = &levels[0];
	for (i = 0; i < nlevels; i++)
		if (old == &levels[i])
			break;
	if (i == nlevels)
		i = 0;

	i += chg;
	if (i >= nlevels)
		i = nlevels - 1;
	if (i < 0)
		i = 0;
	return (&levels[i]);
}

/*--------------------------------------------------------------------*/

void
VSC_Destroy(struct vsc **vscp, struct vsm *vsm)
{
	struct vsc *vsc;
	struct vsc_sf *sf, *sf2;

	TAKE_OBJ_NOTNULL(vsc, vscp, VSC_MAGIC);

	VTAILQ_FOREACH_SAFE(sf, &vsc->sf_list, list, sf2) {
		CHECK_OBJ_NOTNULL(sf, VSC_SF_MAGIC);
		VTAILQ_REMOVE(&vsc->sf_list, sf, list);
		free(sf->pattern);
		FREE_OBJ(sf);
	}

	vsc_del_segs(vsc, vsm, &vsc->segs);
	assert(VTAILQ_EMPTY(&vsc->docs));
	FREE_OBJ(vsc);
}
