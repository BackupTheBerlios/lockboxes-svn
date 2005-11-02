/*
 * This file is part of the original implementation of the lockbox API for the
 * Linux kernel.
 *
 * Copyright 2005 Troy Rollo
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include "linux/lockbox.h"

extern int lockbox_call(void *data);

int
lkb_open(	int		shelf,
		char const *	name)
{
	lockbox_open_struct s;

	s.callid = LKBCALL_OPEN;
	s.shelfid = shelf;
	s.name = name;
	return lockbox_call(&s);
}

int
lkb_create(	int		shelf,
		char const *	name,
		void const *	data,
		size_t		size,
		lockbox_acl const *acl)
{
	lockbox_create_struct s;

	s.callid = LKBCALL_CREATE;
	s.shelfid = shelf;
	s.name = name;
	s.data = data;
	s.size = size;
	s.acl = acl;
	return lockbox_call(&s);
}

int
lkb_close(	lockbox_t	id)
{
	lockbox_close_struct s;

	s.callid = LKBCALL_CLOSE;
	s.lockboxid = id;
	return lockbox_call(&s);
}

int
lkb_getname(	lockbox_t	id,
		char *		name,
		size_t		bufsize,
		size_t		*sizeneeded)
{
	lockbox_getname_struct s;
	int status;

	s.callid = LKBCALL_GETNAME;
	s.lockboxid = id;
	s.name = name;
	s.bufsize = bufsize;
	s.sizeneeded = 0;
	status = lockbox_call(&s);
	*sizeneeded = s.sizeneeded;
	return status;
}

int
lkb_listboxes(	int		shelf,
		char		*names,
		size_t		bufsize,
		size_t		*sizeneeded)
{
	lockbox_listboxes_struct s;
	int	status;

	s.callid = LKBCALL_LISTBOXES;
	s.shelfid = shelf;
	s.names = names;
	s.bufsize = bufsize;
	s.sizeneeded = 0;
	status = lockbox_call(&s);
	*sizeneeded = s.sizeneeded;
	return status;
}

int
lkb_size(	lockbox_t	id)
{
	lockbox_size_struct s;

	s.callid = LKBCALL_SIZE;
	s.lockboxid = id;
	return lockbox_call(&s);
}

int
lkb_getdata(	lockbox_t	id,
		void		*buffer,
		size_t		bufsize,
		off_t		offset)
{
	lockbox_getdata_struct s;

	s.callid = LKBCALL_GETDATA;
	s.lockboxid = id;
	s.buffer = buffer;
	s.size = bufsize;
	s.offset = offset;
	return lockbox_call(&s);
}

int
lkb_setdata(	lockbox_t	id,
		void	const	*buffer,
		size_t		bufsize,
		off_t		offset)
{
	lockbox_setdata_struct s;

	s.callid = LKBCALL_SETDATA;
	s.lockboxid = id;
	s.buffer = buffer;
	s.size = bufsize;
	s.offset = offset;
	return lockbox_call(&s);
}

int
lkb_setstate(	lockbox_t	id,
		uint32_t	state)
{
	lockbox_getsetstate_struct s;

	s.callid = LKBCALL_SETSTATE;
	s.lockboxid = id;
	s.state = state;
	return lockbox_call(&s);
}

int
lkb_getstate(	lockbox_t	id,
		uint32_t	*state)
{
	lockbox_getsetstate_struct s;
	int	status;

	s.callid = LKBCALL_GETSTATE;
	s.lockboxid = id;
	status = lockbox_call(&s);
	if (!status)
		*state = s.state;
	return status;
}

int
lkb_getacl(	lockbox_t	id,
		lockbox_acl	*acl,
		size_t		size,
		size_t		*sizeneeded)
{
	lockbox_getacl_struct s;
	int	status;

	s.callid = LKBCALL_GETACL;
	s.lockboxid = id;
	s.acl = acl;
	s.size = size;
	s.sizeneeded = 0;
	status = lockbox_call(&s);
	*sizeneeded = s.sizeneeded;
	return status;
}

int
lkb_getusers(	lockbox_t	id)
{
	lockbox_getusers_struct s;

	s.callid = LKBCALL_GETUSERS;
	s.lockboxid = id;
	return lockbox_call(&s);
}

int
lkb_setacl(	lockbox_t	id,
		lockbox_acl const *acl)
{
	lockbox_setacl_struct s;

	s.callid = LKBCALL_SETACL;
	s.lockboxid = id;
	s.acl = acl;
	return lockbox_call(&s);
}

int
lkb_setfile(	lockbox_t	id,
		int		fd)
{
	lockbox_setfile_struct s;

	s.callid = LKBCALL_SETFILE;
	s.lockboxid = id;
	s.fd = fd;
	return lockbox_call(&s);
}

int
lkb_getfile(	lockbox_t	id)
{
	lockbox_getfile_struct s;

	s.callid = LKBCALL_GETFILE;
	s.lockboxid = id;
	return lockbox_call(&s);
}

int
lkb_lock(	lockbox_t	id,
		uint32_t	flags)
{
	lockbox_lock_struct s;

	s.callid = LKBCALL_LOCK;
	s.lockboxid = id;
	s.flags = flags;
	return lockbox_call(&s);
}

int
lkb_unlock(	lockbox_t	id)
{
	lockbox_unlock_struct s;

	s.callid = LKBCALL_UNLOCK;
	s.lockboxid = id;
	return lockbox_call(&s);
}

int
lkb_setselectcriterion(	lockbox_t	id,
			uint32_t	type,
			uint32_t	value)
{
	lockbox_setselectcriterion_struct s;

	s.callid = LKBCALL_SETSELC;
	s.lockboxid = id;
	s.type = type;
	s.value = value;
	return lockbox_call(&s);
}

int
lkb_getselectableboxes( size_t		arraysize,
			lockbox_t	*array)
{
	lockbox_getselectableboxes_struct s;

	s.callid = LKBCALL_GETSELBOXES;
	s.arraysize = arraysize;
	s.array = array;
	return lockbox_call(&s);
}

int
lkb_resetallselects(void)
{
	lockbox_resetallselects_struct s;

	s.callid = LKBCALL_RSTSELCS;
	return lockbox_call(&s);
}
