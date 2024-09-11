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
 *
 */

#include "config.h"

#ifdef __linux__

#include <fcntl.h>
#include <grp.h>
#include <linux/magic.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/vfs.h>

#include "mgt/mgt.h"
#include "common/heritage.h"

static int
vjl_set_thp(const char *arg)
{
	int val;

	if (!strcmp(arg, "ignore"))
		return (0);
	if (!strcmp(arg, "enable"))
		val = 0;
	else if (!strcmp(arg, "disable"))
		val = 1;
	else {
		ARGV_ERR(
		    "linux jail: unknown value '%s' for argument transparent_hugepage.\n",
		    arg);
	}
	if (prctl(PR_SET_THP_DISABLE, val, 0, 0, 0) != 0) {
		MGT_Complain(C_ERR,
		    "Could not %s Transparent Hugepage: %s (%d)",
		    arg, VAS_errtxt(errno), errno);
	}
	return (0);
}

static int
vjl_init(char **args)
{
	char **unix_args;
	int ret = 0;
	size_t i;

	if (args == NULL) {
		/* Autoconfig */
		if (vjl_set_thp("disable") != 0)
			return (1);
		return (jail_tech_unix.init(NULL));
	}

	for (i = 0; args[i] != NULL; i++);
	unix_args = calloc(i + 1, sizeof *unix_args);
	AN(unix_args);

	for (i = 0; *args != NULL && ret == 0; args++) {
		if (!strncmp(*args, "transparent_hugepage=",
		    sizeof("transparent_hugepage=") - 1)) {
			ret = vjl_set_thp((*args) + (sizeof("transparent_hugepage=") - 1));
		} else {
			unix_args[i] = *args;
			i++;
		}
	}

	if (ret == 0)
		ret = jail_tech_unix.init(unix_args);
	free(unix_args);
	return (ret);
}

static void
vjl_master(enum jail_master_e jme)
{

	jail_tech_unix.master(jme);
}

static void
vjl_subproc(enum jail_subproc_e jse)
{

	jail_tech_unix.subproc(jse);
	/*
	 * On linux mucking about with uid/gid disables core-dumps,
	 * reenable them again.
	 */
	if (prctl(PR_SET_DUMPABLE, 1) != 0) {
		MGT_Complain(C_INFO,
		    "Could not set dumpable bit.  Core dumps turned off");
	}
}

static int
vjl_make_subdir(const char *dname, const char *what, struct vsb *vsb)
{

	return jail_tech_unix.make_subdir(dname, what, vsb);
}

static int
vjl_make_workdir(const char *dname, const char *what, struct vsb *vsb)
{
	struct statfs info;

	if (jail_tech_unix.make_workdir(dname, what, vsb) != 0)
		return (1);

	vjl_master(JAIL_MASTER_FILE);
	if (statfs(dname, &info) != 0) {
		if (vsb) {
			VSB_printf(vsb,
			    "Could not stat working directory '%s': %s (%d)\n",
			    dname, VAS_errtxt(errno), errno);
		} else {
			MGT_Complain(C_ERR,
			    "Could not stat working directory '%s': %s (%d)",
			    dname, VAS_errtxt(errno), errno);
		}
		return (1);
	}
	if (info.f_type != TMPFS_MAGIC) {
		if (vsb != NULL)
			VSB_printf(vsb,
			    "Working directory not mounted on tmpfs partition\n");
		else
			MGT_Complain(C_INFO,
			    "Working directory not mounted on tmpfs partition");
	}
	vjl_master(JAIL_MASTER_LOW);
	return (0);
}

static void
vjl_fixfd(int fd, enum jail_fixfd_e what)
{

	jail_tech_unix.fixfd(fd, what);
}

const struct jail_tech jail_tech_linux = {
	.magic =	JAIL_TECH_MAGIC,
	.name =		"linux",
	.init =		vjl_init,
	.master =	vjl_master,
	.make_subdir =	vjl_make_subdir,
	.make_workdir =	vjl_make_workdir,
	.fixfd =	vjl_fixfd,
	.subproc =	vjl_subproc,
};

#endif /* __linux__ */
