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

static int fd = -1;

char const lockbox_file_name[] = "/proc/lockbox";

int
lockbox_call(void *data)
{
	if (fd < 0)
	{
		errno = EIO;
		return -1;
	}
	return ioctl(fd, LOCKBOX_IOCTL_CALL, data);
}

int
lkb_openvault(char const *vaultid)
{
	if (fd >= 0)
	{
		errno = EBUSY;
		return -1;
	}

	fd = open(lockbox_file_name, O_RDWR);
	if (fd >= 0)
	{
		lockbox_setvault_struct s;
		int	tmp;

		/* The file descriptor really represents this
		 * process' access to the lockbox, and when
		 * the process execs, the file descriptor should
		 * be closed so that the kernel knows to clean
		 * up any owned lockboxes.
		 */

		s.callid = LKBCALL_SETVAULT;
		s.name = vaultid;
		fcntl(fd, F_SETFD, FD_CLOEXEC);
		if (lockbox_call(&s) < 0)
		{
			tmp = errno;
			close(fd);
			errno = tmp;
			fd = -1;
		}
	}
	return fd;
}

void
lkb_closevault(void)
{
	if (fd != -1)
	{
		close(fd);
		fd = -1;
	}
}

int
lkb_listvaults(	char	*data,
		size_t	bufsize,
		size_t	*sizeneeded)
{
	int	fdtmp = fd;
	int	myfd = 0;
	int	tmp;
	int	status;
	lockbox_listvaults_struct s;

	if (fdtmp == -1)
	{
		fdtmp = open(lockbox_file_name, O_RDWR);
		
		if (fdtmp < 0)
			return -1;	

		myfd = 1;
	}

	status = 0;

	s.callid = LKBCALL_LISTVAULTS;
	s.data = data;
	s.bufsize = bufsize;
	s.sizeneeded = *sizeneeded;

	status = ioctl(fdtmp, LOCKBOX_IOCTL_CALL, &s);
	if (status < 0)
		tmp = errno;
	*sizeneeded = s.sizeneeded;

	if (myfd)
		close(fdtmp);
	if (status < 0)
		errno = tmp;
	return status;
}

int
lkb_createselectfd(	lockbox_select_fd_entry const *entries,
			size_t	count)
{
	int	status;
	int	tmp;

	lockbox_createselectfd_struct s;

	if (fd < 0)
	{
		errno = EIO;
		return;
	}

	s.targetfd = open(lockbox_file_name, O_RDWR);

	if (s.targetfd < 0)
	{
		errno = EIO;
		return;
	}

	s.callid = LKBCALL_CREATESELFD;
	s.entries = entries;
	s.count = count;
	status = lockbox_call(&s);

	if (status < 0)
	{
		tmp = errno;
		close(s.targetfd);
		errno = tmp;
		return -1;
	}
	return s.targetfd;
}
