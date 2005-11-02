/*
 * This file is part of the original implementation of the lockbox API for the
 * Linux kernel.
 *
 * Copyright 2005 Troy Rollo
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/fcntl.h>
#include "lockbox.h"

main(int argc, char **argv)
{
	lockbox_t lb;
	int	fd;
	char	fname[20];

	if (argc != 2)
	{
		fprintf(stderr, "Usage: createbox vaultname\n");
		return 1;
	}
	if (lkb_openvault(argv[1]) < 0)
	{
		perror(argv[1]);
		return 1;
	}
	lb = lkb_create(0, 0, "abcd", 4, 0);
	if (lb == LOCKBOX_ERROR)
	{
		perror("lkb_create");
	}
	else
	{
		char *name =0;
		size_t len;

		if (lkb_getname(lb, name, 0, &len) < 0)
		{
			perror("lkb_getname");
		}
		else
		{
			name = (char *) malloc(len);
			if (lkb_getname(lb, name, len, &len) < 0)
			{
				perror("lkb_getname");
			}
			else
			{
				printf("Name is: %s\n", name);
			}
		}
		if (lkb_lock(lb, LKB_LOCK_DATA) < 0)
			perror("lkb_lock");
		sprintf(fname, "box_%d", getpid());
		printf("File name: %s\n", fname);
		fd = open(fname, O_WRONLY | O_CREAT, 0600);
		if (fd < 0)
			perror(fname);
		else if (lkb_setfile(lb, fd) < 0)
			perror("lkb_setfile");
		sleep(120);
	}
	return 0;
}
