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

#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <stdlib.h>
#include "lockbox.h"

void
dump_line(	int	loc,
		char	*pch,
		int	n)
{
	int	i;

	printf("   %08x:", loc);
	for (i = 0; i < 16; ++i)
	{
		if (i == 8)
			printf(" -");
		if (i < n)
			printf(" %02x", (unsigned char) pch[i]);
		else
			printf("   ");
	}
	printf("  ");
	for (i = 0; i < 16; ++i)
	{
		if (i == 8)
			printf(" - ");
		if (i >= n)
			printf(" ");
		else if (pch[i] >= 32 && pch[i] <= 126)
			printf("%c", pch[i]);
		else
			printf(".");
	}
	printf("\n");
}

char const *
acl_type_text(uint32_t t)
{
	switch (t)
	{
	case LKB_IDTYPE_USER:
		return "User";

	case LKB_IDTYPE_GROUP:
		return "Group";

	case LKB_IDTYPE_WORLD:
		return "World";

	case LKB_IDTYPE_PROCESS:
		return "Process";

	default:
		return "???";
	}
}

char const *
acl_mode_text(uint32_t m)
{
	static char a[11];
	char *c = a;

	if (m & LKB_ACCESS_READ)
		*c++ = 'r';
	else
		*c++ = '-';
	if (m & LKB_ACCESS_WRITE)
		*c++ = 'w';
	else
		*c++ = '-';
	if (m & LKB_ACCESS_LOCK)
		*c++ = 'l';
	else
		*c++ = '-';
	if (m & LKB_ACCESS_GETFD)
		*c++ = 'g';
	else
		*c++ = '-';
	if (m & LKB_ACCESS_SETFD)
		*c++ = 's';
	else
		*c++ = '-';
	if (m & LKB_ACCESS_GETSTATE)
		*c++ = 'G';
	else
		*c++ = '-';
	if (m & LKB_ACCESS_SETSTATE)
		*c++ = 'S';
	else
		*c++ = '-';
	if (m & LKB_ACCESS_GETACL)
		*c++ = 'a';
	else
		*c++ = '-';
	if (m & LKB_ACCESS_SETACL)
		*c++ = 'p';
	else
		*c++ = '-';
	if (m & LKB_ACCESS_OPEN)
		*c++ = 'o';
	else
		*c++ = '-';
	*c = 0;
	return a;
}

int
main(int argc, char **argv)
{
	char	*data = 0;
	size_t	sizeneeded = 0;

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

	do
	{
		if (sizeneeded)
		{
			if (data)
				free(data);
			data = (char *) malloc(sizeneeded);
		}
	} while (lkb_listboxes(0, data, sizeneeded, &sizeneeded) < 0);
	while (*data)
	{
		lockbox_t lb;

		lb = lkb_open(0, data);
		if (lb == LOCKBOX_ERROR)
		{
			perror(data);
		}
		else
		{
			char	line[16];
			int	loc = 0;
			int	n;
			uint32_t state = 0;
			lockbox_acl *pacl = 0;
			size_t	acl_sizeneeded = 0;
			size_t	acl_size;
			int	i;
			int	fd;


			if (lkb_getstate(lb, &state) < 0)
				perror("lkb_getstate");

			printf("%s (%d bytes, state = %08x)\n", data, lkb_size(lb), state);

			printf(" Users: %d\n", lkb_getusers(lb));

			fd = lkb_getfile(lb);

			if (fd < 0)
			{
				perror("lkb_getfile");
			}
			else
			{
				FILE *fp = fdopen(fd, "w");

				fprintf(fp, "Seen by process %d\n", getpid());
				fclose(fp);
			}

			do
			{
				if (pacl)
					free(pacl);
				if (acl_sizeneeded)
					pacl = (lockbox_acl *) malloc(acl_sizeneeded);
				acl_size = acl_sizeneeded;
			} while (lkb_getacl(lb, pacl, acl_size, &acl_sizeneeded));

			if (pacl->la_header.lah_version == LKB_ACL_VERSION)
			{
				printf(" ACL version: %d\n", pacl->la_header.lah_version);
				for (i = 0; i < pacl->la_header.lah_n_entries; ++i)
				{
					printf("  %-12s %5d %s\n",
						acl_type_text(pacl->la_entries[i].lae_idtype),
						pacl->la_entries[i].lae_id,
						acl_mode_text(pacl->la_entries[i].lae_access));
					if (pacl->la_entries[i].lae_idtype == LKB_IDTYPE_WORLD)
						pacl->la_entries[i].lae_access ^= LKB_ACCESS_GETACL;
				}
			}
			if (lkb_setacl(lb, pacl) < 0)
				perror("lkb_setacl");
			free(pacl);
			while ((n = lkb_getdata(lb, line, 16, loc)) > 0)
			{
				dump_line(loc, line, n);
				loc += n;
			}
			if (n < 0)
			{
				perror("lkb_getdata");
			}
			else
			{
				for (i = 0; i < 16; ++i)
					++line[i];
				if (lkb_setdata(lb, line, 4, loc) < 0)
					perror("lkb_setdata");
				if (lkb_setstate(lb, state + 1) < 0)
					perror("lkb_setstate");
			}
			lkb_close(lb);
		}
		data += strlen(data) + 1;
	}
	return 0;
}
