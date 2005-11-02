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
#include "lockbox.h"

int
main(int argc, char **argv)
{
	char	*data = 0;
	size_t	sizeneeded = 0;

	do
	{
		if (sizeneeded)
		{
			if (data)
				free(data);
			data = (char *) malloc(sizeneeded);
		}
	} while (lkb_listvaults(data, sizeneeded, &sizeneeded) < 0);
	while (*data)
	{
		printf("%s\n", data);
		data += strlen(data) + 1;
	}
	return 0;
}
