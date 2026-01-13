/*-
 * Copyright (c) 2006 Verdens Gang AS
 * Copyright (c) 2006-2011 Varnish Software AS
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
 */

#include "config.h"

#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>

#include <sys/mman.h>

#include "cache/cache_varnishd.h"

#include "vapi/vsl_int.h"
#include "waiter/waiter.h"
#include "waiter/waiter_priv.h"
#include "vtim.h"

struct vwp {
	unsigned		magic;
#define VWP_MAGIC		0x4b2cc735
	struct waiter		*waiter;

	int			pipes[2];

	pthread_t		thread;
	struct pollfd		*pollfd;
	struct waited		**idx;
	size_t			npoll;
	size_t			hpoll;

	struct waited **waiter_table;
	pthread_mutex_t table_mutex;
	size_t table_size;
	size_t free_slots;
};

/*--------------------------------------------------------------------
 * It would make much more sense to not use two large vectors, but
 * the poll(2) API forces us to use at least one, so ... KISS.
 */

static void
vwp_extend_pollspace(struct vwp *vwp)
{
	size_t inc;

	if (vwp->npoll < (1<<12))
		inc = (1<<10);
	else if (vwp->npoll < (1<<14))
		inc = (1<<12);
	else if (vwp->npoll < (1<<16))
		inc = (1<<14);
	else
		inc = (1<<16);

	VSL(SLT_Debug, NO_VXID, "Acceptor poll space increased by %zu to %zu",
	    inc, vwp->npoll + inc);

	vwp->pollfd = realloc(vwp->pollfd,
	    (vwp->npoll + inc) * sizeof(*vwp->pollfd));
	AN(vwp->pollfd);
	memset(vwp->pollfd + vwp->npoll, 0, inc * sizeof(*vwp->pollfd));

	vwp->idx = realloc(vwp->idx, (vwp->npoll + inc) * sizeof(*vwp->idx));
	AN(vwp->idx);
	memset(vwp->idx + vwp->npoll, 0, inc * sizeof(*vwp->idx));

	for (; inc > 0; inc--)
		vwp->pollfd[vwp->npoll++].fd = -1;
}

static int vwp_alloc_slot(struct vwp *vwp, struct waited *wp) {
	size_t i;
	int ret = -1;

	fprintf(stderr, "LOCKING : %s %s %d\n", __FILE__, __FUNCTION__, __LINE__);
	pthread_mutex_lock(&vwp->table_mutex);
	fprintf(stderr, "LOCKED : %s %s %d\n", __FILE__, __FUNCTION__, __LINE__);
	for (i = 0; i < vwp->table_size; i++) {
		if (vwp->waiter_table[i] == NULL) {
			vwp->waiter_table[i] = wp;
			vwp->free_slots--;
			ret = (int)i;
			break;
		}
	}
	pthread_mutex_unlock(&vwp->table_mutex);
	fprintf(stderr, "UNLOCKED : %s %s %d\n", __FILE__, __FUNCTION__, __LINE__);
	return ret;
}

static void
vwp_free_slot(struct vwp *vwp, int slot)
{
    if (slot < 0 || (size_t)slot >= vwp->table_size)
        return;
 //    fprintf(stderr, "LOCKING : %s %s %d\n", __FILE__, __FUNCTION__, __LINE__);
 //    pthread_mutex_lock(&vwp->table_mutex);
	// fprintf(stderr, "LOCKED : %s %s %d\n", __FILE__, __FUNCTION__, __LINE__);
    vwp->waiter_table[slot] = NULL;
    vwp->free_slots++;
    // pthread_mutex_unlock(&vwp->table_mutex);
    // fprintf(stderr, "UNLOCKED : %s %s %d\n", __FILE__, __FUNCTION__, __LINE__);
}

static void
vwp_grow_table(struct vwp *vwp)
{
    size_t new_size = vwp->table_size * 2;
    struct waited **new_table;
    new_table = realloc(vwp->waiter_table, new_size * sizeof(*new_table));
    AN(new_table);
    munmap(new_table, vwp->table_size * sizeof(*new_table));
    new_table = mmap(NULL, new_size * sizeof(*new_table), PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    AN(new_table);
    memcpy(new_table, vwp->waiter_table, vwp->table_size * sizeof(*new_table));
    memset(new_table + vwp->table_size, 0, (new_size - vwp->table_size) * sizeof(*new_table));
    vwp->waiter_table = new_table;
    vwp->table_size = new_size;
    VSL(SLT_Debug, NO_VXID, "vwp: Table grown to %zu slots", new_size);
}

/*--------------------------------------------------------------------*/

static void
vwp_add(struct vwp *vwp, struct waited *wp)
{

	CHECK_OBJ_NOTNULL(wp, WAITED_MAGIC);
	VSL(SLT_Debug, NO_VXID, "vwp: ADD %d", wp->fd);
	CHECK_OBJ_NOTNULL(vwp, VWP_MAGIC);
	if (vwp->hpoll == vwp->npoll)
		vwp_extend_pollspace(vwp);
	assert(vwp->hpoll < vwp->npoll);
	assert(vwp->pollfd[vwp->hpoll].fd == -1);
	AZ(vwp->idx[vwp->hpoll]);
	vwp->pollfd[vwp->hpoll].fd = wp->fd;
	vwp->pollfd[vwp->hpoll].events = POLLIN;
	vwp->idx[vwp->hpoll] = wp;
	vwp->hpoll++;
	Wait_HeapInsert(vwp->waiter, wp);
}

static void
vwp_del(struct vwp *vwp, int n)
{
	vwp->hpoll--;
	if (n != vwp->hpoll) {
		vwp->pollfd[n] = vwp->pollfd[vwp->hpoll];
		vwp->idx[n] = vwp->idx[vwp->hpoll];
	}
	memset(&vwp->pollfd[vwp->hpoll], 0, sizeof(*vwp->pollfd));
	vwp->pollfd[vwp->hpoll].fd = -1;
	vwp->idx[vwp->hpoll] = NULL;
}

/*--------------------------------------------------------------------*/

static void
vwp_dopipe(struct vwp *vwp)
{
	int slots[128];
	ssize_t ss;
	int i, slot;
	struct waited *wp;

	ss = read(vwp->pipes[0], slots, sizeof slots);
	assert(ss > 0);
	i = 0;
	// fprintf(stderr, "ZEBI : w: ");
	// zprint_ptr(w);
	// fprintf(stderr, "\n");
	while (ss > 0) {
		slot = slots[i++];
		ss -= sizeof slot;
		wp = NULL;
		fprintf(stderr, "LOCKING : %s %s %d\n", __FILE__, __FUNCTION__, __LINE__);
		pthread_mutex_lock(&vwp->table_mutex);
		fprintf(stderr, "LOCKED : %s %s %d\n", __FILE__, __FUNCTION__, __LINE__);
		if ((size_t)slot < vwp->table_size && vwp->waiter_table[slot] != NULL) {
			wp = vwp->waiter_table[slot];
			vwp_free_slot(vwp, slot);
		}
		pthread_mutex_unlock(&vwp->table_mutex);
		fprintf(stderr, "UNLOCKED : %s %s %d\n", __FILE__, __FUNCTION__, __LINE__);

		if (wp == NULL) {
			VSL(SLT_Error, NO_VXID, "vwp: Invalid/missing slot %d", slot);
			continue;
		}
		CHECK_OBJ_NOTNULL(wp, WAITED_MAGIC);
		assert(wp->fd > 0);
		vwp_add(vwp, wp);
		// if (w[i] == NULL) {
		// 	assert(ss == sizeof w[0]);
		// 	assert(vwp->hpoll == 1);
		// 	pthread_exit(NULL);
		// }
		// struct waited *ww;
		// ww = zmkptr(w[i], (unsigned long)w[i]);
		// fprintf(stderr, "READ ZEBI : w[i]: ");
		// zprint_ptr(ww);
		// fprintf(stderr, "\n");
		// CHECK_OBJ_NOTNULL(ww, WAITED_MAGIC);
		// assert(ww->fd > 0);			// no stdin
		// vwp_add(vwp, w[i++]);
		// ss -= sizeof w[0];
	}
}

/*--------------------------------------------------------------------*/

static void *
vwp_main(void *priv)
{
	int t, v;
	struct vwp *vwp;
	struct waiter *w;
	struct waited *wp;
	double now, then;
	size_t z;

	THR_SetName("cache-poll");
	THR_Init();
	CAST_OBJ_NOTNULL(vwp, priv, VWP_MAGIC);
	w = vwp->waiter;

	while (1) {
		then = Wait_HeapDue(w, &wp);
		if (wp == NULL)
			t = -1;
		else
			t = (int)floor(1e3 * (then - VTIM_real()));
		assert(vwp->hpoll > 0);
		AN(vwp->pollfd);
		v = poll(vwp->pollfd, vwp->hpoll, t);
		assert(v >= 0);
		now = VTIM_real();
		if (vwp->pollfd[0].revents)
			v--;
		for (z = 1; z < vwp->hpoll;) {
			assert(vwp->pollfd[z].fd != vwp->pipes[0]);
			wp = vwp->idx[z];
			CHECK_OBJ_NOTNULL(wp, WAITED_MAGIC);

			if (v == 0 && Wait_HeapDue(w, NULL) > now)
				break;
			if (vwp->pollfd[z].revents)
				v--;
			then = Wait_When(wp);
			if (then <= now) {
				AN(Wait_HeapDelete(w, wp));
				Wait_Call(w, wp, WAITER_TIMEOUT, now);
				vwp_del(vwp, z);
			} else if (vwp->pollfd[z].revents & POLLIN) {
				assert(wp->fd > 0);
				assert(wp->fd == vwp->pollfd[z].fd);
				AN(Wait_HeapDelete(w, wp));
				Wait_Call(w, wp, WAITER_ACTION, now);
				vwp_del(vwp, z);
			} else {
				z++;
			}
		}
		if (vwp->pollfd[0].revents)
			vwp_dopipe(vwp);
	}
	NEEDLESS(return (NULL));
}

/*--------------------------------------------------------------------*/

static int v_matchproto_(waiter_enter_f)
vwp_enter(void *priv, struct waited *wp)
{
	struct vwp *vwp;
	int slot;

	CAST_OBJ_NOTNULL(vwp, priv, VWP_MAGIC);

	// fprintf(stderr, "WRITE ZEBI : w[i]: ");
	// zprint_ptr(wp);
	// fprintf(stderr, "\n");
	slot = vwp_alloc_slot(vwp, wp);
	if (slot < 0) {
		if (vwp->free_slots == 0)
			vwp_grow_table(vwp);
		slot = vwp_alloc_slot(vwp, wp);
		if (slot < 0)
			return (-1);
	}
	VSL(SLT_Debug, NO_VXID, "vwp: ENTER slot %d for fd %d", slot, wp->fd);

	if (write(vwp->pipes[1], &slot, sizeof slot) != sizeof slot)
		return (-1);
	return (0);
}

/*--------------------------------------------------------------------*/

static void v_matchproto_(waiter_init_f)
vwp_init(struct waiter *w)
{
    struct vwp *vwp;
    CHECK_OBJ_NOTNULL(w, WAITER_MAGIC);
    vwp = w->priv;
    INIT_OBJ(vwp, VWP_MAGIC);
    vwp->waiter = w;
    AZ(pipe(vwp->pipes));
    vwp->hpoll = 1;
    vwp_extend_pollspace(vwp);
    vwp->pollfd[0].fd = vwp->pipes[0];
    vwp->pollfd[0].events = POLLIN;
    // New: Init shared table
    vwp->table_size = 1024;  // Initial size; grow as needed
    vwp->waiter_table = mmap(NULL, vwp->table_size * sizeof(*vwp->waiter_table),
                             PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    AN(vwp->waiter_table);  // Check alloc
    memset(vwp->waiter_table, 0, vwp->table_size * sizeof(*vwp->waiter_table));
    vwp->free_slots = vwp->table_size;
    pthread_mutex_init(&vwp->table_mutex, NULL);
    PTOK(pthread_create(&vwp->thread, NULL, vwp_main, vwp));
}

/*--------------------------------------------------------------------
 * It is the callers responsibility to trigger all fd's waited on to
 * fail somehow.
 */

static void v_matchproto_(waiter_fini_f)
vwp_fini(struct waiter *w)
{
	struct vwp *vwp;
	void *vp;

	CAST_OBJ_NOTNULL(vwp, w->priv, VWP_MAGIC);
	vp = NULL;
	while (vwp->hpoll > 1)
		VTIM_sleep(0.1);
	// XXX: set write pipe blocking
	assert(write(vwp->pipes[1], &vp, sizeof vp) == sizeof vp);
	PTOK(pthread_join(vwp->thread, &vp));

	pthread_mutex_destroy(&vwp->table_mutex);
	munmap(vwp->waiter_table, vwp->table_size * sizeof(*vwp->waiter_table));

	closefd(&vwp->pipes[0]);
	closefd(&vwp->pipes[1]);
	free(vwp->pollfd);
	free(vwp->idx);
}

/*--------------------------------------------------------------------*/

#include "waiter/mgt_waiter.h"

const struct waiter_impl waiter_poll = {
	.name =		"poll",
	.init =		vwp_init,
	.fini =		vwp_fini,
	.enter =	vwp_enter,
	.size =		sizeof(struct vwp),
};
