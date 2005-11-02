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

#ifndef __LOCKBOX_H
#define __LOCKBOX_H

typedef int32_t	lockbox_t;

#define	LOCKBOX_ERROR ((lockbox_t) -1)

typedef struct
{
	uint32_t		lae_idtype;
	uint32_t		lae_id;
	uint32_t		lae_access;
	uint32_t		lae_reserved;
} lockbox_acl_entry;

typedef struct
{
	uint32_t		lah_version;
	uint32_t		lah_n_entries;
} lockbox_acl_header;

typedef struct
{
	lockbox_acl_header	la_header;
	lockbox_acl_entry	la_entries[1];
} lockbox_acl;

typedef struct
{
	uint32_t	lscs_criterion;
	uint32_t	lscs_value;
} lockbox_select_criterion_setting;

typedef struct
{
	lockbox_t	lsfe_id;
	size_t		lsfe_criteria;
	lockbox_select_criterion_setting const *lsfe_settings;
} lockbox_select_fd_entry;

#define	LKB_ACL_SIZE(e)	(sizeof(lockbox_acl_header) + \
			 (e) * sizeof(lockbox_acl_entry))

#define	LKB_ACL_VERSION		0

#define	LKB_IDTYPE_USER		0
#define LKB_IDTYPE_GROUP	1
#define	LKB_IDTYPE_WORLD	2
#define	LKB_IDTYPE_PROCESS	3

#define	LKB_ACCESS_READ		0x00000001
#define	LKB_ACCESS_WRITE	0x00000002
#define	LKB_ACCESS_LOCK		0x00000004
#define	LKB_ACCESS_GETFD	0x00000008
#define	LKB_ACCESS_SETFD	0x00000010
#define	LKB_ACCESS_GETSTATE	0x00000020
#define	LKB_ACCESS_SETSTATE	0x00000040
#define	LKB_ACCESS_GETACL	0x00000080
#define	LKB_ACCESS_SETACL	0x00000100
#define	LKB_ACCESS_OPEN		0x00000200

#define LKB_ACCESS_ALL		0x000003ff

#define	LKB_LOCK_DATA		0x00000001
#define	LKB_LOCK_FILE		0x00000002
#define	LKB_LOCK_STATE		0x00000004
#define	LKB_LOCK_ACL		0x00000008

#define LKB_LOCK_NOBLOCK	0x40000000

#define LKB_LOCK_ALL		0x0000000f

/* From the API definition, a process can only access one
 * vault at a time. The file descriptor returned by openvault
 * is primarily for use in a call to select(), where it can
 * be tested for exceptional conditions.
 *
 * The file descriptor is initially set to close on exec.
 */

int		lkb_openvault(	char const *	vaultid);
void		lkb_closevault(	void);
int		lkb_listvaults(	char *		data,
				size_t		bufsize,
				size_t		*sizeneeded);

/* Shelves
 *
 * The shelf describes the type of content in the lockbox,
 * which is meaningful to processes using the vault. A process
 * can enumerate all lockboxes on a shelf.
 *
 * Low numbered shelves are to be preferred because they are
 * faster to access. Applications should start their shelf
 * usage at 0 and use contiguous numbering for their shelves.
 */

int		lkb_listboxes(	int		shelf,
				char *		names,
				size_t		bufsize,
				size_t		*sizeneeded);

/* Create, open, close.
 * If "name" NULL, the kernel will allocate
 * a lockbox name of the form "#nnnnnnnn", where 'n' is
 * a hexadecimal digit.
 *
 * In lkb_create, the acl can be passed as a null pointer, in
 * which case the permissions will be:
 *
 *	user = LKB_ACCESS_ALL
 *	world = LKB_ACCESS_READ | LKB_ACCESS_OPEN
 */

lockbox_t	lkb_create(	int		shelf,
				char const *	name,
				void const *	data,
				size_t		size,
				lockbox_acl const *acl);
lockbox_t	lkb_open(	int		shelf,
				char const *	name);
int		lkb_close(	lockbox_t	id);

/* Lock and unlock a lockbox */

int		lkb_lock(	lockbox_t	id,
				uint32_t	flags);
int		lkb_unlock(	lockbox_t	id);

/* Get and set various things about a lockbox */

	/* The name of the lockbox. Primarily useful
	 * when you asked the kernel to assign the
	 * lockbox a name on a shelf (in which case the
	 * required buffer size is predictable).
	 */

int		lkb_getname(	lockbox_t	id,
				char *		name,
				size_t		bufsize,
				size_t		*sizeneeded);

	/* The data in the lockbox. Note that setdata
	 * may increase the size of the lock box, but
	 * not decrease it.
	 */

int		lkb_size(	lockbox_t	id);
int		lkb_getdata(	lockbox_t	id,
				void *		buffer,
				size_t		bufsize,
				off_t		offset);
int		lkb_setdata(	lockbox_t	id,
				void const *	buffer,
				size_t		bufsize,
				off_t		offset);

	/* Set the state of a lockbox. This is a single
	 * number that can be used for signalling. Select
	 * will return when any bit in the state transitions
	 * from 0 to 1.
	 */

int		lkb_setstate(	lockbox_t	id,
				uint32_t	state);
int		lkb_getstate(	lockbox_t	id,
				uint32_t	*state);

	/* Gets or sets the file associated with a lockbox.
	 * Useful for passing file descriptors across process
	 * boundaries.
	 */

int		lkb_setfile(	lockbox_t	id,
				int		fd);
int		lkb_getfile(	lockbox_t	id);

	/* Gets the number of outstanding users on a lockbox.
	 * This allows a process that provides services to
	 * close the lockbox when it has no more client users.
	 * Select will return if the number of users changes.
	 */

int		lkb_getusers(	lockbox_t	id);

	/* The Access Control List for the lockbox.
	 */

int		lkb_setacl(	lockbox_t	id,
				lockbox_acl const *acl);
int		lkb_getacl(	lockbox_t	id,
				lockbox_acl	*acl,
				size_t		size,
				size_t		*sizeneeded);

/* Calls to set the criteria on a lockbox that will cause
 * select() on the file descriptor to return.
 */
#define	LKB_SELECT_USERS_LESS_THAN	0
#define	LKB_SELECT_USERS_GREATER_THAN	1
#define	LKB_SELECT_FLAGS		2
#define	LKB_SELECT_LOCKAVAIL		3

#define	LKB_SELECT_DISABLE_USERS_LT	0
#define LKB_SELECT_DISABLE_USERS_GT	(~(uint32_t)0)
#define	LKB_SELECT_ALL_FLAGS		(~(uint32_t)0)

int		lkb_setselectcriterion(	lockbox_t	id,
					uint32_t	type,
					uint32_t	value);
int		lkb_getselectableboxes(	size_t		arraysize,
					lockbox_t	*array);
int		lkb_resetallselects(	void);

int		lkb_createselectfd(	lockbox_select_fd_entry const *entries,
					size_t		count);

#endif

